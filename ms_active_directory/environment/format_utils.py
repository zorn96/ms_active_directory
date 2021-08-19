import ipaddress

from ms_active_directory import logging_utils

from ldap3 import (
    KERBEROS,
    NTLM,
)

from ldap3.utils.dn import (
    parse_dn,
)

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


def format_hostname_or_ip_and_port_to_uri(host_or_ip: str, port: str, is_ipv6_fmt: bool=None):
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
