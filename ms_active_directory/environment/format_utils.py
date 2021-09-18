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

import ipaddress
import socket


from ldap3 import (
    KERBEROS,
    NTLM,
)

from ldap3.utils.dn import (
    parse_dn,
)

from ms_active_directory import logging_utils
from ms_active_directory.environment.ldap.ldap_format_utils import is_dn
from ms_active_directory.exceptions import InvalidDomainParameterException


logger = logging_utils.get_logger()


def format_computer_name_for_authentication(computer_name: str, domain: str, authentication_mechanism: str):
    original_name = computer_name
    if is_dn(computer_name):
        parse_dn(computer_name)
        name_format = 'domain\\sAMAccountName' if authentication_mechanism == NTLM else 'sAMAccountName@domain'
        raise InvalidDomainParameterException('Computer names may not be specified as distinguished names for LDAP '
                                              'authentication. Please specify the computer name in the format {}'
                                              .format(name_format))

    adjusted_computer_name = computer_name.lower()
    # split up domain and computer name if they're already both included. @ and \ are not valid
    # sAMAccountName characters, so we can split on those safely.
    # if the name came with a domain in it, use that. it likely matches the domain passed in, but
    # it could be a subdomain in which case we don't want to tamper with it
    if '@' in adjusted_computer_name:
        adjusted_computer_name, domain = adjusted_computer_name.split('@')
    elif '\\' in adjusted_computer_name:
        domain, adjusted_computer_name = adjusted_computer_name.split('\\')

    # add a $ at the end of the sAMAccountName if it's not there, as is convention for computers
    if not adjusted_computer_name.endswith('$'):
        adjusted_computer_name = computer_name + '$'

    # put the name and domain into the right format
    if authentication_mechanism == NTLM:
        # user needs to be 'domain\computer_samaccount_name'
        adjusted_computer_name = domain.lower() + '\\' + adjusted_computer_name
    elif authentication_mechanism == KERBEROS:
        # user needs to be 'computer_samaccount_name@domain'
        adjusted_computer_name = adjusted_computer_name + '@' + domain.lower()
    logger.debug('Adjusted computer name %s to be %s for LDAP authentication using %s',
                 original_name, adjusted_computer_name, authentication_mechanism)
    return adjusted_computer_name


def format_hostname_or_ip_and_port_to_uri(host_or_ip: str, port: str, is_ipv6_fmt: bool = None):
    """ Combine what is either an ipv4 address, ipv6 address, or hostname and (optionally) a port
    into the proper format.
    """
    if port is None or port == '':
        return host_or_ip

    if is_ipv6_fmt is None:
        try:
            ipaddress.IPv6Address(host_or_ip)
            is_ipv6_fmt = True
        except ValueError:
            pass

    if is_ipv6_fmt:
        return '[{}]:{}'.format(host_or_ip, port)
    return '{}:{}'.format(host_or_ip, port)


def get_system_default_computer_name():
    computer_name = socket.gethostname()
    # if there's dots (e.g. our computer is server1.com) just take the first piece
    if '.' in computer_name:
        computer_name = computer_name.split('.')[0]
    logger.info('Using computer hostname (or its first component after splitting on dots) as computer name %s ',
                computer_name)
    return computer_name
