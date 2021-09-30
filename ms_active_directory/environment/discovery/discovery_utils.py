""" This module contains helper functions for discovering an Active Directory domain and its
domain controllers via DNS, as well as for sorting them by reachability.
"""
# Created in August 2021
#
# Author: Azaria Zornberg
#
# Copyright 2021 - 2021 Azaria Zornberg
#
# This file is part of ms_active_directory
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import dns.exception
import dns.resolver
import socket
import time

import ms_active_directory.environment.format_utils as format_utils

# environmental interactions are lightweight and primarily IO-bounded, not CPU-bounded.
# most of our time is spent waiting on replies, so we use a thread pool instead of a
# process pool
from concurrent.futures import ThreadPoolExecutor
from functools import partial
from dns.rdatatype import SRV, RdataType
from ldap3 import Connection, Server, DSA
from typing import List, Callable

from ms_active_directory.environment.discovery.discovery_constants import (
    DNS_TIMEOUT_SECONDS,
    KERBEROS_DNS_SRV_FORMAT,
    KERBEROS_SITE_AWARE_DNS_SRV_FORMAT,
    LDAP_DNS_SRV_FORMAT,
    LDAP_SITE_AWARE_DNS_SRV_FORMAT,
)
from ms_active_directory import logging_utils


logger = logging_utils.get_logger()


def discover_ldap_domain_controllers_in_domain(domain: str, site: str=None, dns_nameservers: List[str]=None,
                                               source_ip: str=None, server_limit: int=None, secure: bool=True):
    """ Take in an AD domain and discover the LDAP servers in the domain that are domain
    controllers. Then order them to try and optimize going to the closest/fastest/highest priority
    servers first.
    :param domain: The string dns name of the domain.
    :param site: The string name of a site within the domain. If specified, only controllers within
                 the site will be returned.
    :param dns_nameservers: The nameservers to use for DNS lookups to discover LDAP servers. If not
                            specified, the system DNS nameservers will be used.
    :param source_ip: The source IP to use for DNS queries and when checking RTT to LDAP servers.
    :param server_limit: An integer limit on the number of controllers returned. After sorting by RTT,
                         if specified, only the fastest server_limit controllers will be returned.
    :param secure: If true, only controllers capable of securing LDAP communication using StartTLS
                   will be returned, and TLS negotiation time will be accounted for in the RTT evaluation.
    :returns: a tuple consisting of an ordered list of the fastest LDAP uris (which combines the hostname and
              protocol), and the full ordered list of LDAP uris (which combines the hostname and protocol).
    """
    logger.info('Discovering LDAP servers for domain %s in DNS', domain)
    ldap_srv = LDAP_DNS_SRV_FORMAT.format(domain=domain)
    if site:
        ldap_srv = LDAP_SITE_AWARE_DNS_SRV_FORMAT.format(site=site, domain=domain)
    all_ldap_records = _resolve_record_in_dns(ldap_srv, SRV, dns_nameservers, source_ip)
    return _order_ldap_servers_by_rtt(all_ldap_records, server_limit, source_ip, secure)


def discover_kdc_domain_controllers_in_domain(domain: str, site: str=None, dns_nameservers: List[str]=None,
                                              source_ip: str=None, server_limit: int=None):
    """ Take in an AD domain and discover the KDCs in the domain that are domain controllers. Then
    order them to try and optimize going to the closest/fastest/highest priority servers first.
    :param domain: The string dns name of the domain.
    :param site: The string name of a site within the domain. If specified, only controllers within
                 the site will be returned.
    :param dns_nameservers: The nameservers to use for DNS lookups to discover LDAP servers. If not
                            specified, the system DNS nameservers will be used.
    :param source_ip: The source IP to use for DNS queries and when checking RTT to kerberos servers.
    :param server_limit: An integer limit on the number of controllers returned. After sorting by RTT,
                         if specified, only the fastest server_limit controllers will be returned.
    :returns: a tuple consisting of a truncated list of the ordered list of KDC uris (which combines the hostname
              and port to reach out on), and the full list of KDC uris (which combines the hostname and port to
              reach out on).
    """
    logger.info('Discovering Kerberos servers for domain %s in DNS', domain)
    krb_srv = KERBEROS_DNS_SRV_FORMAT.format(domain=domain)
    if site:
        krb_srv = KERBEROS_SITE_AWARE_DNS_SRV_FORMAT.format(site=site, domain=domain)
    all_kdc_records = _resolve_record_in_dns(krb_srv, SRV, dns_nameservers, source_ip)
    return _order_kdcs_by_rtt(all_kdc_records, server_limit, source_ip)


def _resolve_record_in_dns(record_name: str, record_type: RdataType, dns_nameservers: List[str], source_ip: str):
    """ Take a record and record type and resolve it in DNS.

    Returns a list of tuples where each tuple is in the format (host, port, priority, weight)
    sorted by priority and then weight.
    """
    temp_resolver = dns.resolver.Resolver()
    temp_resolver.timeout = DNS_TIMEOUT_SECONDS
    temp_resolver.lifetime = DNS_TIMEOUT_SECONDS
    if dns_nameservers:
        logger.debug('Using the following nameservers for dns lookup instead of the default system ones %s',
                     dns_nameservers)
        temp_resolver.nameservers = dns_nameservers
    # DNS queries are normally UDP. However, the best practices from microsoft for DNS are that
    # you use TCP if your result will be greater than 512 bytes. It states that DNS may truncate
    # results greater than 512 bytes.
    # If a record maps to a lot of results (like a service record for a large domain) then our
    # result can easily exceed 512 bytes, so we use tcp directly for lookups here, rather than
    # wait for udp to fail and then fallback.
    try:
        resolved_records = temp_resolver.resolve(record_name, record_type, tcp=True,
                                                 source=source_ip)
    except dns.exception.DNSException as dns_ex:
        logger.info('Unable to query DNS for record %s due to: %s', record_name, dns_ex)
        return []
    except Exception as ex:
        logger.warning('Unexpected exception occurred when querying DNS for record %s: %s',
                       record_name, ex)
        return []

    # turn our DNS records into more manageable tuples in the form:
    # (URI, Port, Priority, Weight)
    record_tuples = [(record.target.to_text(omit_final_dot=True), record.port, record.priority, record.weight)
                     for record in resolved_records]
    # A lower priority value (closer to 0) means that a record should be preferred.
    # Weight is used to rank order records of equal priority, and a higher value weight (further
    # above 0) means that a record should be preferred.
    # So we sort ascending, first by priority, and then by -1 * weight
    record_tuples = sorted(record_tuples, key=lambda record_tuple: (record_tuple[2], -1*record_tuple[3]))
    logger.debug('Records returned in %s lookup for %s ordered by priority and weight: %s',
                 record_type, record_name, record_tuples)
    return record_tuples


def _order_ldap_servers_by_rtt(ldap_server_records: List[tuple], server_limit: int, source_ip: str, secure: bool):
    """ Take in a list of LDAP server records and determine the reachability and round trip time to each.
    Order them by RTT, fastest first, and drop unreachable servers. If there's more than our limit,
    trim the length based on our limit.
    """
    lookup_rtt_fns = []
    processed_host_port_tuples = set()
    for server_tuple in ldap_server_records:
        # windows AD when upgrading from 2008/2012 to 2016/2019 can end up with duplicate SRV records due to issues
        # with case sensitivity in registering records. but DNS names ARE case insensitive.
        # in case a domain's admin hasn't corrected these records, remove duplicates so that we don't waste time
        # /end up with multiple duplicate URIs returned
        # https://docs.microsoft.com/en-us/troubleshoot/windows-server/networking/dns-registers-duplicate-srv-records-for-dc
        # we don't care about weight and priority anymore if ordering by RTT
        server_host, server_port, _, _ = server_tuple
        host_port_tuple = (server_host.lower(), server_port) # cast to lowercase for case insensitivity
        if host_port_tuple in processed_host_port_tuples:
            continue
        processed_host_port_tuples.add(host_port_tuple)
        # build our function for checking availability and round trip time
        fn = partial(_check_ldap_server_availability_and_rtt, server_host, server_port, source_ip, secure)
        lookup_rtt_fns.append(fn)
    return _process_sort_return_rtt_ordering_results(lookup_rtt_fns, 'LDAP', server_limit)


def _order_kdcs_by_rtt(kdc_server_records: List[tuple], server_limit: int, source_ip: str):
    """ Take in a list of KDC server records and determine the reachability and round trip time to each.
    Order them by RTT, fastest first, and drop unreachable servers. If there's more than our limit,
    trim the length based on our limit.
    """
    lookup_rtt_fns = []
    processed_host_port_tuples = set()
    for server_tuple in kdc_server_records:
        # windows AD when upgrading from 2008/2012 to 2016/2019 can end up with duplicate SRV records due to issues
        # with case sensitivity in registering records. but DNS names ARE case insensitive.
        # in case a domain's admin hasn't corrected these records, remove duplicates so that we don't waste time
        # /end up with multiple duplicate URIs returned
        # https://docs.microsoft.com/en-us/troubleshoot/windows-server/networking/dns-registers-duplicate-srv-records-for-dc
        # we don't care about weight and priority anymore if ordering by RTT
        server_host, server_port, _, _ = server_tuple
        host_port_tuple = (server_host.lower(), server_port) # cast to lowercase for case insensitivity
        if host_port_tuple in processed_host_port_tuples:
            continue
        processed_host_port_tuples.add(host_port_tuple)
        # build our function for checking availability and round trip time
        fn = partial(_check_kdc_availability_and_rtt, server_host, server_port, source_ip)
        lookup_rtt_fns.append(fn)
    return _process_sort_return_rtt_ordering_results(lookup_rtt_fns, 'KDC', server_limit)


def _process_sort_return_rtt_ordering_results(lookup_rtt_fns: List[Callable], uri_desc: str,
                                              maximum_result_list_length: int):
    """ Take in a list of lookup functions that measure round trip time to the server,
    and execute all of those coroutines in parallel.

    Each coroutine returns a tuple of (round trip time, composed URI). We then filter our any
    URIs that could not be reached within our connection timeout and sort by round trip time.
    We then return the URIs in sorted order.
    """
    logger.info('Sorting %s %s servers by round trip time and removing unreachable servers',
                len(lookup_rtt_fns), uri_desc)
    rtt_results = []
    with ThreadPoolExecutor() as executor:
        running_tasks = [executor.submit(lookup_fn) for lookup_fn in lookup_rtt_fns]
        for task in running_tasks:
            rtt_results.append(task.result())
    # Drop results that are None values, as they indicate unreachable servers.
    rtt_uri_tuples = [result_tuple for result_tuple in rtt_results
                      if result_tuple is not None and result_tuple[0] is not None]
    # this will sort ascending by the first key by default, which is the round trip time. so it
    # will end up sorting the closest servers first
    rtt_uri_tuples = sorted(rtt_uri_tuples)
    logger.debug('%s servers sorted by round trip time to them: %s', uri_desc, rtt_uri_tuples)

    result_list = [uri for _, uri in rtt_uri_tuples]
    short_list = result_list
    # if we have a limit on the number of servers we want, return it
    if maximum_result_list_length and len(result_list) > maximum_result_list_length:
        short_list = result_list[:maximum_result_list_length]
        logger.info('Trimming list of %s servers to the fastest %s to reply due to total number exceeding our limit. '
                    'Remaining servers: %s', uri_desc, maximum_result_list_length, short_list)
    return short_list


def _check_ldap_server_availability_and_rtt(server_host: str, server_port: str, source_ip: str, secure: bool):
    """ Even if an LDAP server is registered in DNS, it might not be reachable for us. DNS is
    centralized, but data centers may have multiple network partitions, and there may be firewalls
    or air gaps in our way.
    A server could also be down.

    This will check if a server is available and return a tuple of the URI and the time it took to
    make that check.
    This isn't exactly letting us know how quickly we can query the server, because its internal
    processing power for heavyweight queries might not be directly related to how quickly it
    responds to availability checks. But it's a decent and quick approximation.

    If secure is True, then we'll start TLS on any LDAP connection to ensure that we can negotiate
    TLS with the server. Otherwise, we'll just use plaintext LDAP.

    Returns None for any unreachable servers.
    """
    ldap_uri = 'ldap://{}:{}'.format(server_host, server_port)
    # by using get_info=DSA we perform what's sometimes referred to as form of "LDAP ping".
    # we query the root DSE, which can be done without binding
    server = Server(ldap_uri, get_info=DSA)
    conn = Connection(server, source_address=source_ip)
    start = time.time()
    try:
        conn.open()
        if secure:
            if not conn.start_tls():
                logger.debug('LDAP server %s was reachable on port %s but failed to start secure communication')
                return None
        end = time.time()
    except:
        if secure:
            logger.debug('LDAP server %s was unreachable on port %s or raised an exception establishing secure communication on that port',
                         server_host, server_port)
        else:
            logger.debug('LDAP server %s was unreachable on port %s', server_host, server_port)
        return None
    return end - start, ldap_uri


def _check_kdc_availability_and_rtt(server_host: str, server_port: str, source_ip: str):
    """ Even if an KDC server is registered in DNS, it might not be reachable for us. DNS is
    centralized, but data centers may have multiple network partitions, and there may be firewalls
    or air gaps in our way.
    A server could also be down.

    This will check if a server is available and return a tuple of the URI and the time it took to
    make that check.
    This isn't exactly letting us know how quickly we can query the server, because its internal
    processing power for heavyweight queries might not be directly related to how quickly it
    responds to availability checks. But it's a decent and quick approximation.

    Returns None if the server is unreachable.
    """
    candidates = []
    source_ip = source_ip if source_ip else ''  # socket library wants an empty string for dynamic assignment
    # hostname - try both ipv4 and ipv6
    kdc_uri = format_utils.format_hostname_or_ip_and_port_to_uri(server_host, server_port,
                                                                 is_ipv6_fmt=False)

    test_socket4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    addr_tuple4 = (server_host, server_port)

    test_socket6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    addr_tuple6 = (server_host, server_port, 0, 0)

    candidates.append((test_socket6, addr_tuple6))
    candidates.append((test_socket4, addr_tuple4))

    for temp_socket, temp_addr_tuple in candidates:
        try:
            try:
                # bind before time evaluation so that the underlying network stack isn't factored in,
                # since dynamic port assignment time varies
                temp_socket.bind((source_ip, 0))  # 0 for dynamically assigned port
                start = time.time()
                temp_socket.connect(temp_addr_tuple)
                end = time.time()
                return end - start, kdc_uri
            except socket.error:
                logger.debug('KDC server %s was unreachable on port %s', server_host, server_port)
            finally:
                try:
                    temp_socket.shutdown(socket.SHUT_RDWR)
                    temp_socket.close()
                except socket.error:
                    pass
        except Exception:
            logger.exception('Unexpected exception when checking connectivity to %s on port %s using source ip %s '
                             'and temporary socket %s', server_host, server_port, source_ip, temp_socket)
    return None
