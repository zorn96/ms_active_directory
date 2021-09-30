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

import copy
import pytz

from datetime import datetime, timedelta, timezone
from ldap3 import (
    ANONYMOUS,
    BASE,
    Connection,
    FIRST,
    KERBEROS,
    SAFE_RESTARTABLE,
    SASL,
    Server,
    ServerPool,
    SIMPLE,
    SUBTREE,
    Tls,
)
from ldap3.core.connection import SASL_AVAILABLE_MECHANISMS
from ssl import (
    OP_NO_SSLv2,
    OP_NO_SSLv3,
    OP_NO_TLSv1,
    OP_NO_TLSv1_1,
    CERT_NONE,
    CERT_REQUIRED,
)
from typing import List, Union

# local imports come after imports from other libraries
from ms_active_directory import logging_utils
from ms_active_directory.core.ad_session import ADSession
from ms_active_directory.core.managed_ad_objects import ManagedADComputer
from ms_active_directory.environment.constants import ADFunctionalLevel
from ms_active_directory.environment.discovery.discovery_utils import discover_kdc_domain_controllers_in_domain, \
    discover_ldap_domain_controllers_in_domain
from ms_active_directory.environment.format_utils import format_computer_name_for_authentication, \
    get_system_default_computer_name
from ms_active_directory.environment.kerberos.kerberos_constants import DEFAULT_KRB5_KEYTAB_FILE_LOCATION
from ms_active_directory.environment.ldap import trust_constants
from ms_active_directory.environment.ldap.ldap_constants import (
    AD_ATTRIBUTE_GET_ALL_NON_VIRTUAL_ATTRS,
    AD_ATTRIBUTE_ENCRYPTION_TYPES,
    AD_ATTRIBUTE_NETBIOS_NAME,
    AD_ATTRIBUTE_OBJECT_CLASS,
    AD_DOMAIN_DNS_ROOT,
    AD_DOMAIN_FUNCTIONAL_LEVEL,
    AD_DOMAIN_SUPPORTED_SASL_MECHANISMS,
    AD_DOMAIN_TIME,
    AD_TRUSTED_DOMAIN_FQDN,
    AD_TRUSTED_DOMAIN_NETBIOS_NAME,
    AD_TRUST_ATTRIBUTES,
    AD_TRUST_DIRECTION,
    AD_TRUST_TYPE,
    AD_TRUST_POSIX_OFFSET,
    DOMAIN_WIDE_PARTITIONS_CONTAINER,
    FIND_ANYTHING_FILTER,
    TRUSTED_DOMAIN_OBJECT_CLASS,
    VALUE_TO_FIND_ANY_WITH_ATTRIBUTE_POPULATED,
)
from ms_active_directory.environment.ldap.ldap_format_utils import (
    construct_ldap_base_dn_from_domain,
    process_ldap3_conn_return_value,
    remove_ad_search_refs,
)
from ms_active_directory.environment.security.security_config_constants import ADEncryptionType
from ms_active_directory.exceptions import (
    DomainConnectException,
    DomainSearchException,
    InvalidDomainParameterException,
    SessionTransferException,
    TrustedDomainConversionException,
)

logger = logging_utils.get_logger()


def join_ad_domain(domain_dns_name: str, admin_username: str, admin_password: str,
                   authentication_mechanism: str = SIMPLE, ad_site: str = None, computer_name: str = None,
                   computer_location: str = None, computer_password: str = None,
                   computer_encryption_types: List[Union[str, ADEncryptionType]] = None,
                   computer_hostnames: List[str] = None, computer_services: List[str] = None,
                   supports_legacy_behavior: bool = False,
                   computer_key_file_path: str = DEFAULT_KRB5_KEYTAB_FILE_LOCATION,
                   **additional_account_attributes) -> ManagedADComputer:
    """ A super simple 'join a domain' function that requires minimal input - the domain dns name and admin credentials
    to use in the join process.
    Given those basic inputs, the domain's nearest controllers are automatically discovered and an account is made
    with strong security settings. The account's attributes follow AD naming conventions based on the computer's
    hostname by default.
    :param domain_dns_name: The DNS name of the domain being joined.
    :param admin_username: The username of a user or computer with the rights to create the computer.
                           This username should be formatted based on the authentication protocol being used.
                           For example, DOMAIN\\username for NTLM as opposed to username@DOMAIN for GSSAPI, or
                           a distinguished name for SIMPLE.
                           If `old_computer_password` is specified, then this account only needs permission to
                           change the password of the computer being taken over, which is different from the reset
                           password permission.
    :param admin_password: The password for the user. Optional, as SASL authentication mechanisms can use
                           `sasl_credentials` specified as a keyword argument, and things like KERBEROS will use
                           default system kerberos credentials if they're available.
    :param authentication_mechanism: An LDAP authentication mechanism or SASL mechanism. If 'SASL' is specified,
                                     then the keyword argument `sasl_mechanism` must also be specified. Valid values
                                     include all authentication mechanisms and SASL mechanisms from the ldap3
                                     library, such as SIMPLE, NTLM, KERBEROS, etc.
    :param ad_site: Optional. The site within the active directory domain where our communication should be confined.
    :param computer_name: The name of the computer to take over in the domain. This should be the sAMAccountName
                          of the computer, though if computer has a trailing $ in its sAMAccountName and that is
                          omitted, that's ok. If not specified, we will attempt to find a computer with a name
                          matching the local system's hostname.
    :param computer_location: The location in which to create the computer. This may be specified as an LDAP-style
                              relative distinguished name (e.g. OU=ServiceMachines,OU=Machines) or a windows path
                              style canonical name (e.g. example.com/Machines/ServiceMachines).
                              If not specified, defaults to CN=Computers which is the standard default for AD.
    :param computer_password: The password to set for the computer when taking it over. If not specified, a random
                              120 character password will be generated and set.
    :param computer_encryption_types: A list of encryption types, based on the ADEncryptionType enum, to enable on
                                      the account created. These may be strings or enums; if they are strings,
                                      they should be strings of the encryption types as written in kerberos
                                      RFCs or in AD management tools, and we will try to map them to enums and
                                      raise an error if they don't match any supported values.
                                      AES256-SHA1, AES128-SHA1, and RC4-HMAC encryption types are supported. DES
                                      encryption types aren not.
                                      If not specified, defaults to [AES256-SHA1].
    :param computer_hostnames: Hostnames to set for the computer. These will be used to set the dns hostname
                               attribute in AD. If not specified, the computer hostnames will default to
                               [`computer_name`, `computer_name`.`domain`] which is the AD standard default.
    :param computer_services: Services to enable on the computers hostnames. These services dictate what clients
                              can get kerberos tickets for when communicating with this computer, and this property
                              is used with `computer_hostnames` to set the service principal names for the computer.
                              For example, having `nfs` specified as a service principal is necessary if you want
                              to run an NFS server on this computer and have clients get kerberos tickets for
                              mounting shares; having `ssh` specified as a service principal is necessary for
                              clients to request kerberos tickets for sshing to the computer.
                              If not specified, defaults to `HOST` which is the standard AD default service.
                              `HOST` covers a wide variety of services, including `cifs`, `ssh`, and many others
                              depending on your domain. Determining exactly what services are covered by `HOST`
                              in your domain requires checking the aliases set on a domain controller.
    :param supports_legacy_behavior: If `True`, then an error will be raised if the computer name is longer than
                                     15 characters (not including the trailing $). This is because various older
                                     systems such as NTLM, certain UNC path applications, Netbios, etc. cannot
                                     use names longer than 15 characters. This name cannot be changed after
                                     creation, so this is important to control at creation time.
                                     If not specified, defaults to `False`.
    :param computer_key_file_path: The path of where to write the keytab file for the computer after taking it over.
                                   This will include keys for both user and server keys for the computer.
                                   If not specified, defaults to /etc/krb5.keytab
    :param additional_account_attributes: Additional keyword argument can be specified to set other LDAP attributes
                                          of the computer that are not covered above, or where the above controls
                                          are not sufficiently granular. For example, `userAccountControl` could
                                          be used to set the user account control values for the computer if it's
                                          desired to set it differently from the default (e.g. create a computer
                                          in a disabled state and enable it later).
    :returns: A ManagedADComputer object representing the computer created.
    """
    domain = ADDomain(domain_dns_name, site=ad_site)
    return domain.join(admin_username, admin_password, authentication_mechanism, computer_name=computer_name,
                       computer_location=computer_location, computer_password=computer_password,
                       computer_hostnames=computer_hostnames, computer_services=computer_services,
                       computer_encryption_types=computer_encryption_types,
                       supports_legacy_behavior=supports_legacy_behavior,
                       computer_key_file_path=computer_key_file_path, **additional_account_attributes)


def join_ad_domain_by_taking_over_existing_computer(domain_dns_name: str, admin_username: str, admin_password: str,
                                                    authentication_mechanism: str = SIMPLE, ad_site: str = None,
                                                    computer_name: str = None, computer_password: str = None,
                                                    old_computer_password: str = None,
                                                    computer_key_file_path: str = DEFAULT_KRB5_KEYTAB_FILE_LOCATION,
                                                    **additional_connection_attributes) -> ManagedADComputer:
    """ A super simple 'join a domain' function using pre-created computer accounts, which requires minimal input -
    the domain dns name and admin credentials to use in the join process.
    Specifying a computer name explicitly for the account to take over is also highly recommended.

    Given those basic inputs, the domain's nearest controllers are automatically discovered and the computer account
    with the specified computer name is found and taken over so it can represent the local system in the domain,
    and the local system can act as it.
    :param domain_dns_name: The DNS name of the domain being joined.
    :param admin_username: The username of a user or computer with the rights to reset the password of the computer
                           being taken over.
                           This username should be formatted based on the authentication protocol being used.
                           For example, DOMAIN\\username for NTLM as opposed to username@DOMAIN for GSSAPI, or
                           a distinguished name for SIMPLE.
                           If `old_computer_password` is specified, then this account only needs permission to
                           change the password of the computer being taken over, which is different from the reset
                           password permission.
    :param admin_password: The password for the user. Optional, as SASL authentication mechanisms can use
                           `sasl_credentials` specified as a keyword argument, and things like KERBEROS will use
                           default system kerberos credentials if they're available.
    :param authentication_mechanism: An LDAP authentication mechanism or SASL mechanism. If 'SASL' is specified,
                                     then the keyword argument `sasl_mechanism` must also be specified. Valid values
                                     include all authentication mechanisms and SASL mechanisms from the ldap3
                                     library, such as SIMPLE, NTLM, KERBEROS, etc.
    :param ad_site: Optional. The site within the active directory domain where our communication should be confined.
    :param computer_name: The name of the computer to take over in the domain. This should be the sAMAccountName
                          of the computer, though if computer has a trailing $ in its sAMAccountName and that is
                          omitted, that's ok. If not specified, we will attempt to find a computer with a name
                          matching the local system's hostname.
    :param computer_password: The password to set for the computer when taking it over. If not specified, a random
                              120 character password will be generated and set.
    :param old_computer_password: The current password of the computer being taken over. If specified, the action
                                  of taking over the computer will use a "change password" operation, which is less
                                  privileged than a "reset password" operation. So specifying this reduces the
                                  permissions needed by the user specified.
    :param computer_key_file_path: The path of where to write the keytab file for the computer after taking it over.
                                   This will include keys for both user and server keys for the computer.
                                   If not specified, defaults to /etc/krb5.keytab
    :param additional_connection_attributes: Additional keyword arguments may be specified for any properties of
                                             the `Connection` object from the `ldap3` library that is desired to
                                             be set on the connection used in the session created for taking over
                                             the computer. Examples include `sasl_credentials`, `client_strategy`,
                                             `cred_store`, and `pool_lifetime`.
    :returns: A ManagedADComputer object representing the computer taken over.
    """
    domain = ADDomain(domain_dns_name, site=ad_site)
    return domain.join_by_taking_over_existing_computer(admin_username, admin_password, authentication_mechanism,
                                                        computer_name=computer_name,
                                                        computer_password=computer_password,
                                                        old_computer_password=old_computer_password,
                                                        computer_key_file_path=computer_key_file_path,
                                                        **additional_connection_attributes)


def join_ad_domain_using_session(ad_session: ADSession, computer_name=None, computer_location=None,
                                 computer_password=None, computer_encryption_types=None, computer_hostnames=None,
                                 computer_services=None, supports_legacy_behavior=False,
                                 computer_key_file_path=DEFAULT_KRB5_KEYTAB_FILE_LOCATION,
                                 **additional_account_attributes) -> ManagedADComputer:
    """ A fairly simple 'join a domain' function that requires minimal input - an AD session.
    Given those basic inputs, the domain's nearest controllers are automatically discovered and an account is made
    with strong security settings. The account's attributes follow AD naming conventions based on the computer's
    hostname by default.
    By providing an AD session, one can build a connection to the domain however they so choose and then use it to
    join this computer, so you don't even need to necessarily use user credentials.
    :param ad_session: The ADSession object representing a connection with the domain to be joined.
    :param computer_name: The name of the computer to take over in the domain. This should be the sAMAccountName
                          of the computer, though if computer has a trailing $ in its sAMAccountName and that is
                          omitted, that's ok. If not specified, we will attempt to find a computer with a name
                          matching the local system's hostname.
    :param computer_location: The location in which to create the computer. This may be specified as an LDAP-style
                              relative distinguished name (e.g. OU=ServiceMachines,OU=Machines) or a windows path
                              style canonical name (e.g. example.com/Machines/ServiceMachines).
                              If not specified, defaults to CN=Computers which is the standard default for AD.
    :param computer_password: The password to set for the computer when taking it over. If not specified, a random
                              120 character password will be generated and set.
    :param computer_encryption_types: A list of encryption types, based on the ADEncryptionType enum, to enable on
                                      the account created. These may be strings or enums; if they are strings,
                                      they should be strings of the encryption types as written in kerberos
                                      RFCs or in AD management tools, and we will try to map them to enums and
                                      raise an error if they don't match any supported values.
                                      AES256-SHA1, AES128-SHA1, and RC4-HMAC encryption types are supported. DES
                                      encryption types aren not.
                                      If not specified, defaults to [AES256-SHA1].
    :param computer_hostnames: Hostnames to set for the computer. These will be used to set the dns hostname
                               attribute in AD. If not specified, the computer hostnames will default to
                               [`computer_name`, `computer_name`.`domain`] which is the AD standard default.
    :param computer_services: Services to enable on the computers hostnames. These services dictate what clients
                              can get kerberos tickets for when communicating with this computer, and this property
                              is used with `computer_hostnames` to set the service principal names for the computer.
                              For example, having `nfs` specified as a service principal is necessary if you want
                              to run an NFS server on this computer and have clients get kerberos tickets for
                              mounting shares; having `ssh` specified as a service principal is necessary for
                              clients to request kerberos tickets for sshing to the computer.
                              If not specified, defaults to `HOST` which is the standard AD default service.
                              `HOST` covers a wide variety of services, including `cifs`, `ssh`, and many others
                              depending on your domain. Determining exactly what services are covered by `HOST`
                              in your domain requires checking the aliases set on a domain controller.
    :param supports_legacy_behavior: If `True`, then an error will be raised if the computer name is longer than
                                     15 characters (not including the trailing $). This is because various older
                                     systems such as NTLM, certain UNC path applications, Netbios, etc. cannot
                                     use names longer than 15 characters. This name cannot be changed after
                                     creation, so this is important to control at creation time.
                                     If not specified, defaults to `False`.
    :param computer_key_file_path: The path of where to write the keytab file for the computer after taking it over.
                                   This will include keys for both user and server keys for the computer.
                                   If not specified, defaults to /etc/krb5.keytab
    :param additional_account_attributes: Additional keyword argument can be specified to set other LDAP attributes
                                          of the computer that are not covered above, or where the above controls
                                          are not sufficiently granular. For example, `userAccountControl` could
                                          be used to set the user account control values for the computer if it's
                                          desired to set it differently from the default (e.g. create a computer
                                          in a disabled state and enable it later).
    :returns: A ManagedADComputer object representing the computer created.
    """
    # for joining a domain, default to using the local machine's hostname as a computer name
    if computer_name is None:
        computer_name = get_system_default_computer_name()
    logger.info('Attempting to join computer to domain %s with name %s', ad_session.get_domain_dns_name(),
                computer_name)
    computer = ad_session.create_computer(computer_name, computer_location=computer_location,
                                          computer_password=computer_password,
                                          encryption_types=computer_encryption_types, hostnames=computer_hostnames,
                                          services=computer_services, supports_legacy_behavior=supports_legacy_behavior,
                                          **additional_account_attributes)
    if computer_key_file_path is not None:
        computer.write_full_keytab_file_for_computer(computer_key_file_path)
    logger.info('Successfully joined computer to domain %s with name %s', ad_session.get_domain_dns_name(),
                computer_name)
    return computer


def join_ad_domain_by_taking_over_existing_computer_using_session(
        ad_session: ADSession, computer_name=None, computer_password=None, old_computer_password=None,
        computer_key_file_path=DEFAULT_KRB5_KEYTAB_FILE_LOCATION) -> ManagedADComputer:
    """ A fairly simple 'join a domain' function using pre-created accounts, which requires minimal input - an AD
    session. Specifying the name of the computer to takeover explicitly is also encouraged.

    Given those basic inputs, the domain's nearest controllers are automatically discovered and an account is found
    with the computer name specified.
    That account is then taken over so that it can be controlled by the local system, and kerberos keys and such are
    generated for it.

    By providing an AD session, one can build a connection to the domain however they so choose and then use it to
    join this computer, so you don't even need to necessarily use user credentials.
    :param ad_session: The ADSession object representing a connection with the domain to be joined.
    :param computer_name: The name of the computer to take over in the domain. This should be the sAMAccountName
                          of the computer, though if computer has a trailing $ in its sAMAccountName and that is
                          omitted, that's ok. If not specified, we will attempt to find a computer with a name
                          matching the local system's hostname.
    :param computer_password: The password to set for the computer when taking it over. If not specified, a random
                              120 character password will be generated and set.
    :param old_computer_password: The current password of the computer being taken over. If specified, the action
                                  of taking over the computer will use a "change password" operation, which is less
                                  privileged than a "reset password" operation. So specifying this reduces the
                                  permissions needed by the user specified.
    :param computer_key_file_path: The path of where to write the keytab file for the computer after taking it over.
                                   This will include keys for both user and server keys for the computer.
                                   If not specified, defaults to /etc/krb5.keytab
    :returns: A ManagedADComputer object representing the computer taken over.
    """
    # for joining a domain, default to using the local machine's hostname as a computer name
    if computer_name is None:
        computer_name = get_system_default_computer_name()
        logger.warning('No computer name was specified for joining via computer takeover. This is unusual and relies '
                       'implicitly on the computers in the domain matching this library in terms of how they decide '
                       'on the computer name, and may cause errors. The name being used is %s', computer_name)
    logger.info('Attempting to join computer to domain %s by taking over account with name %s',
                ad_session.get_domain_dns_name(), computer_name)
    computer = ad_session.take_over_existing_computer(computer_name, computer_password=computer_password,
                                                      old_computer_password=old_computer_password)
    if computer_key_file_path is not None:
        computer.write_full_keytab_file_for_computer(computer_key_file_path)
    logger.info('Successfully joined computer to domain %s by taking over computer with name %s',
                ad_session.get_domain_dns_name(), computer_name)
    return computer


class ADDomain:

    def __init__(self, domain: str, site: str = None,
                 ldap_servers_or_uris: List = None,
                 kerberos_uris: List[str] = None,
                 encrypt_connections: bool = True,
                 ca_certificates_file_path: str = None,
                 discover_ldap_servers: bool = True,
                 discover_kerberos_servers: bool = True,
                 dns_nameservers: List[str] = None,
                 source_ip: str = None,
                 netbios_name: str = None):
        """ Initialize an interface for defining an AD domain and interacting with it.
        :param domain: The DNS name of the Active Directory domain that this object represents.
        :param site: The Active Directory site to operate within. This is only relevant if LDAP or
                     kerberos servers are discovered in DNS, as there's site-specific records.
                     If set, only hosts within the specified site will be used.
        :param ldap_servers_or_uris: A list of either Server objects from the ldap3 library, or
                                     string LDAP uris. If specified, they will be used to establish
                                     sessions with the domain.
        :param kerberos_uris: A list of string kerberos server uris. These can be IPs (and the default
                              kerberos port of 88 will be used) or IP:port combinations.
        :param encrypt_connections: Whether or not LDAP connections with the domain will be secured
                                    using TLS. This must be True for join functionality to work,
                                    as passwords can only be set over secure connections.
                                    If not specified, defaults to True. If LDAP server objects are
                                    provided with ssl enabled or ldaps:// uris are provided, then
                                    connections to those servers will be encrypted because of the
                                    inherent behavior of such configurations.
        :param ca_certificates_file_path: A path to CA certificates to be used to establish trust
                                          with LDAP servers when securing connections. If not
                                          specified, then TLS will not check the peer certificate.
                                          If LDAP server objects are specified, then their TLS
                                          settings will be used rather than anything set in this
                                          variable. It is only used when discovering servers or
                                          using string URIs, so Server objects can be used if
                                          different CAs sign different servers' certificates
                                          due to regional CAs or something similar.
                                          If not specified, defaults to None.
        :param discover_ldap_servers: If true, and LDAP servers/uris are not specified, then LDAP
                                      servers for the domain will be discovered in DNS.
                                      If not specified, defaults to True.
        :param discover_kerberos_servers: If true, and kerberos uris are not specified, then kerberos
                                          servers for the domain will be discovered in DNS.
                                          If not specified, defaults to True.
        :param dns_nameservers: A list of strings indicating the IP addresses of DNS servers to use
                                when discovering servers for the domain. These may be IPv4 or IPv6
                                addresses.
                                If not specified, defaults to what's configured in /etc/resolv.conf on
                                POSIX systems, and extracting nameservers from registry keys on windows.
                                Defaults to None.
        :param source_ip: A source IP address to use for both DNS and LDAP connections established for
                          this domain. If not specified, defaults to automatic assignment of IP using
                          underlying system networking.
                          Defaults to None.
        :param netbios_name: The netbios name of this domain, which is relevant for a variety of functions.
                             If this is set, then we won't search the domain for the information.
                             This can be set by users, but isn't needed. It's primarily here to avoid
                             extra lookups when creating ADDomain objects from ADTrustedDomain objects, as
                             the netbios name is already known.
        """
        self.domain = domain.lower()  # cast to lowercase
        self.site = site.lower() if site else None
        self.encrypt_connections = encrypt_connections
        self.ca_certificates_file_path = ca_certificates_file_path
        self.ldap_servers = []
        self.ldap_uris = []
        self.kerberos_uris = []
        self.dns_nameservers = dns_nameservers
        self.source_ip = source_ip
        self.netbios_name = netbios_name
        # discover ldap servers and kerberos servers if we weren't provided any and weren't told not to
        if not ldap_servers_or_uris and discover_ldap_servers:
            ldap_servers_or_uris = discover_ldap_domain_controllers_in_domain(self.domain, site=self.site,
                                                                              dns_nameservers=self.dns_nameservers,
                                                                              source_ip=self.source_ip,
                                                                              secure=self.encrypt_connections)
        # discover kerberos servers if we weren't provided any and weren't told not to
        if not kerberos_uris and discover_kerberos_servers:
            kerberos_uris = discover_kdc_domain_controllers_in_domain(self.domain, site=self.site,
                                                                      dns_nameservers=self.dns_nameservers,
                                                                      source_ip=self.source_ip)

        # handle the fact that user-provided ldap servers could be servers or strings
        if ldap_servers_or_uris:
            self.set_ldap_servers_or_uris(ldap_servers_or_uris)

        if kerberos_uris:
            self.set_kerberos_uris(kerberos_uris)

    def get_domain_dns_name(self) -> str:
        return self.domain

    def get_ldap_servers(self) -> List[Server]:
        return [self._copy_ldap_server(serv) for serv in self.ldap_servers]

    def get_ldap_uris(self) -> List[str]:
        return copy.deepcopy(self.ldap_uris)

    def get_kerberos_uris(self) -> List[str]:
        return copy.deepcopy(self.kerberos_uris)

    def _copy_ldap_server(self, serv: Server) -> Server:
        """ Copies an LDAP Server object. The normal python copy doesn't work on Server objects because
        they have locks in them. But sharing server objects across threads/connections/sessions/etc.
        can cause a lot of issues where shared state gets messed up by failed queries or changes in
        one place. So we "copy" the important attributes.
        """
        return Server(serv.host, port=serv.port, use_ssl=serv.ssl,
                      allowed_referral_hosts=serv.allowed_referral_hosts,
                      get_info=serv.get_info, tls=serv.tls, formatter=serv.custom_formatter,
                      connect_timeout=serv.connect_timeout, mode=serv.mode, validator=serv.custom_validator)

    def set_ldap_servers_or_uris(self, ldap_servers_or_uris: List):
        """ Set our list of LDAP servers or LDAP URIs. The list provided can be a list of
        Server objects, URIs, or a mixture.
        """
        ldap_uris = []
        ldap_server_objs = []
        # users can specify Server objects if they want a custom Tls setting for
        # each one, but if they provide strings then we just make our own for each
        for serv in ldap_servers_or_uris:
            if isinstance(serv, str):
                # pass through whatever CA certs file we got, and disable all TLS below
                # 1.2 by default
                tls_setting = None
                if self.encrypt_connections:
                    # only check peer certs if we have CAs
                    checking = CERT_REQUIRED if self.ca_certificates_file_path else CERT_NONE
                    tls_setting = Tls(ca_certs_file=self.ca_certificates_file_path,
                                      ssl_options=[OP_NO_SSLv2, OP_NO_SSLv3, OP_NO_TLSv1,
                                                   OP_NO_TLSv1_1],
                                      validate=checking)
                ldap_server_objs.append(Server(serv, tls=tls_setting))
                ldap_uris.append(serv)
            elif isinstance(serv, Server):
                # extract the uri for list of the server uris we're using, and copy the server object
                copied_server = self._copy_ldap_server(serv)
                ldap_server_objs.append(copied_server)
                ldap_uris.append(serv.name)
            else:
                raise InvalidDomainParameterException('Invalid type for element of ldap server list, {}; '
                                                      'elements must be strings or Server objects'.format(type(serv)))
        self.ldap_servers = ldap_server_objs
        self.ldap_uris = ldap_uris

    def set_kerberos_uris(self, kerberos_uris: List):
        """ Sets our kerberos server uris """
        for serv in kerberos_uris:
            if not isinstance(serv, str):
                raise InvalidDomainParameterException('Invalid type for element of kerberos server list, {}; '
                                                      'elements must be strings'.format(type(serv)))
        self.kerberos_uris = kerberos_uris

    def is_close_in_time_to_localhost(self, ldap_connection: Connection = None,
                                      allowed_drift_seconds: int = None) -> bool:
        """ Check if we're close in time to the domain.
        This is primarily useful for kerberos and TLS negotiation health.
        Optionally, an existing connection can be used. If one is not specified, an anonymous LDAP
        connection will be created and used.
        :param ldap_connection: An ldap3 connection to the domain, optional.
        :param allowed_drift_seconds: The number of seconds considered "close", defaults to 5 minutes.
                                      5 minutes is the standard allowable drift for kerberos.
        :returns: A boolean indicating whether we're within allowed_drift_seconds seconds of the domain time.
        """
        if allowed_drift_seconds is None:
            allowed_drift_seconds = 300
        domain_time = self.find_current_time(ldap_connection)
        local_time = datetime.now(tz=timezone.utc)
        diff = domain_time - local_time
        if local_time > domain_time:
            diff = local_time - domain_time
        return diff < timedelta(seconds=allowed_drift_seconds)

    def find_current_time(self, ldap_connection: Connection = None) -> datetime:
        """ Find the current time for this domain. This is useful for detecting drift that can cause
        Kerberos and TLS issues.
        Optionally, an existing connection can be used. If one is not specified, an anonymous LDAP
        connection will be created and used.
        :param ldap_connection: An ldap3 connection to the domain, optional.
        :returns: A datetime object representing the time.
        """
        if ldap_connection is None:
            logger.info('Creating a new anonymous connection to read domain time')
            # we just need an anonymous session to read this information
            ldap_connection = self.create_session_as_user().get_ldap_connection()

        res = ldap_connection.search(search_base='', search_filter=FIND_ANYTHING_FILTER,
                                     # querying for time as an attribute explicitly doesn't work since it's not a real
                                     # ldap attribute in any rfc
                                     search_scope=BASE, attributes=[AD_ATTRIBUTE_GET_ALL_NON_VIRTUAL_ATTRS],
                                     size_limit=1)
        success, result, response, _ = process_ldap3_conn_return_value(ldap_connection, res)
        search_err = result['result'] != 0
        if search_err:
            raise DomainSearchException('Failed to search the domain to query the current time.')
        base_attrs = response[0]['attributes']
        # time comes back as a 1-item list in the format ["20210809080919.0Z"]
        # that's a date string yyyyMMddHHmmss.0Z
        ad_time = base_attrs.get(AD_DOMAIN_TIME)[0]
        useful_time = datetime.strptime(ad_time, '%Y%m%d%H%M%S.0Z')
        return pytz.utc.localize(useful_time)

    def find_functional_level(self, ldap_connection: Connection = None) -> AD_DOMAIN_FUNCTIONAL_LEVEL:
        """ Find the functional level for this domain.
        Optionally, an existing connection can be used. If one is not specified, an anonymous LDAP
        connection will be created and used.
        :param ldap_connection: An ldap3 connection to the domain, optional.
        :returns: An ADVersion enum indicating the functional level.
        """
        if ldap_connection is None:
            logger.info('Creating a new anonymous connection to read the domain functional level')
            # we just need an anonymous session to read this information
            ldap_connection = self.create_session_as_user().get_ldap_connection()

        res = ldap_connection.search(search_base='', search_filter=FIND_ANYTHING_FILTER,
                                     search_scope=BASE, attributes=[AD_ATTRIBUTE_GET_ALL_NON_VIRTUAL_ATTRS],
                                     size_limit=1)
        success, result, response, _ = process_ldap3_conn_return_value(ldap_connection, res)
        search_err = result['result'] != 0
        if search_err:
            raise DomainSearchException('Failed search the domain for its functional level')
        base_attrs = response[0]['attributes']
        # this is a single-item list of a string of the level number, like ["7"]
        level_str = base_attrs.get(AD_DOMAIN_FUNCTIONAL_LEVEL)[0]
        return ADFunctionalLevel.get_functional_level_from_value(int(level_str))

    def find_netbios_name(self, ldap_connection: Connection = None, force_refresh: bool = False) -> str:
        """ Find the netbios name for this domain. Renaming a domain is a huge task and is incredibly rare,
        so this information is cached when first read, and it only re-read if specifically requested.
        Optionally, an existing connection can be used. If one is not specified, an anonymous LDAP
        connection will be created and used.

        :param ldap_connection: An ldap3 connection to the domain, optional.
        :param force_refresh: If set to true, the domain will be searched for the information even if
                              it is already cached. Defaults to false.
        :returns: A string indicating the netbios name of the domain.
        """
        if self.netbios_name is not None and not force_refresh:
            return self.netbios_name

        if ldap_connection is None:
            logger.info('Creating a new anonymous connection to read netbios name')
            # we just need an anonymous session to read this information
            ldap_connection = self.create_session_as_user().get_ldap_connection()
        search_base = DOMAIN_WIDE_PARTITIONS_CONTAINER + ',' + construct_ldap_base_dn_from_domain(self.domain)
        search_filter = ('(&({}={})({}={}))'.format(AD_DOMAIN_DNS_ROOT, self.domain, AD_ATTRIBUTE_NETBIOS_NAME,
                                                    VALUE_TO_FIND_ANY_WITH_ATTRIBUTE_POPULATED))

        res = ldap_connection.search(search_base=search_base, search_filter=search_filter,
                                     search_scope=SUBTREE, attributes=[AD_ATTRIBUTE_NETBIOS_NAME],
                                     size_limit=1)
        success, result, response, _ = process_ldap3_conn_return_value(ldap_connection, res)
        search_err = result['result'] != 0
        if search_err:
            raise DomainSearchException('Failed search the domain for its netbios name. This may be due to the '
                                        'domain being unreachable or due to a permission issue. Raw result: {}'
                                        .format(result))

        entities = remove_ad_search_refs(response)
        if len(entities) == 0:
            raise DomainSearchException('No results were found with a netbios name in the domain. This may be a '
                                        'results of a domain misconfiguration issue.')
        nb_name = entities[0]['attributes'][AD_ATTRIBUTE_NETBIOS_NAME]
        logger.info('Found netbios name %s for domain %s', nb_name, self.domain)
        self.netbios_name = nb_name
        return self.netbios_name

    def find_supported_sasl_mechanisms(self, ldap_connection: Connection = None) -> List[str]:
        """ Find the supported SASL mechanisms for this domain.
        Optionally, an existing connection can be used. If one is not specified, an anonymous LDAP
        connection will be created and used.
        :param ldap_connection: An ldap3 connection to the domain, optional.
        :returns: A list of strings indicating the supported SASL mechanisms for the domain.
                  ex: ['GSSAPI', 'GSS-SPNEGO', 'EXTERNAL']
        """
        if ldap_connection is None:
            logger.info('Creating a new anonymous connection to read domain supported SASL mechanisms')
            # we just need an anonymous session to read this information
            ldap_connection = self.create_session_as_user().get_ldap_connection()

        res = ldap_connection.search(search_base='', search_filter=FIND_ANYTHING_FILTER,
                                     search_scope=BASE, attributes=[AD_DOMAIN_SUPPORTED_SASL_MECHANISMS],
                                     size_limit=1)
        success, result, response, _ = process_ldap3_conn_return_value(ldap_connection, res)
        search_err = result['result'] != 0
        if search_err:
            raise DomainSearchException('Failed to search the domain for supported SASL mechanisms.')
        base_attrs = response[0]['attributes']
        return base_attrs.get(AD_DOMAIN_SUPPORTED_SASL_MECHANISMS, [])

    def find_trusted_domains(self, ldap_connection: Connection = None) -> List['ADTrustedDomain']:
        """ Find the trusted domains for this domain.
        An LDAP connection is technically optional, as some domains allow enumeration of trust
        relationships by anonymous users, but a connection is likely needed. If one is not specified,
        an anonymous LDAP connection will be created and used.

        :param ldap_connection: An ldap3 connection to the domain, optional.
        :returns: A list of ADTrustedDomain objects
        """
        if ldap_connection is None:
            logger.info('Creating a new anonymous connection to enumerate trusted domains')
            # we can try to read this information with an anonymous connection
            ldap_connection = self.create_session_as_user().get_ldap_connection()

        current_user = ldap_connection.extend.standard.who_am_i()
        using_real_user = (not current_user)  # for help in good error messages

        search_base = construct_ldap_base_dn_from_domain(self.domain)
        search_filter = '({}={})'.format(AD_ATTRIBUTE_OBJECT_CLASS, TRUSTED_DOMAIN_OBJECT_CLASS)
        attributes = [
            AD_ATTRIBUTE_ENCRYPTION_TYPES,
            AD_TRUSTED_DOMAIN_FQDN,
            AD_TRUSTED_DOMAIN_NETBIOS_NAME,
            AD_TRUST_ATTRIBUTES,
            AD_TRUST_DIRECTION,
            AD_TRUST_TYPE,
            AD_TRUST_POSIX_OFFSET,
        ]
        # theoretically, with this subtree search, we could get a lot of results. so we should do a paginated
        # search. but realistically, there shouldn't be THAT many trusted domains. default page size is 100,
        # and having 100 trusted domains is ridiculous
        res = ldap_connection.search(search_base=search_base, search_filter=search_filter,
                                     search_scope=SUBTREE, attributes=attributes)
        success, result, response, _ = process_ldap3_conn_return_value(ldap_connection, res)
        search_err = result['result'] != 0
        if search_err:
            err_msg = ('Failed to search for trusted domains within the domain. This may have occurred if '
                       'enumeration of trusted domains is not supported by anonymous users. If that is the '
                       'case, you may wish to try again and specify a connection.')
            if using_real_user:
                err_msg = ('Failed to search for trusted domains within the domain. This may have occurred '
                           'if reading trust information is restricted to more privileged users than the one '
                           'used for the connection to the domain.')
            raise DomainSearchException(err_msg)

        entities = remove_ad_search_refs(response)
        trusted_domains = [ADTrustedDomain(self, entry['attributes']) for entry in entities]
        logger.info('Found %s trusted domain in %s', len(trusted_domains), self.domain)
        return trusted_domains

    def refresh_ldap_server_discovery(self):
        """ Re-discover LDAP servers in DNS for the domain and redo the sorting by RTT.
        This can update our list of LDAP servers for future connections, allowing faster servers to be
        moved up in priority, unavailable servers to be removed from the list, and previously unavailable
        servers to be added.
        """
        ldap_uris = discover_ldap_domain_controllers_in_domain(self.domain, site=self.site,
                                                               secure=self.encrypt_connections,
                                                               dns_nameservers=self.dns_nameservers,
                                                               source_ip=self.source_ip)
        self.set_ldap_servers_or_uris(ldap_uris)

    def refresh_kerberos_server_discovery(self):
        """ Re-discover Kerberos servers in DNS for the domain and redo the sorting by RTT.
        This can update our list of KDCs for future use by callers, allowing faster servers to be
        moved up in priority, unavailable servers to be removed from the list, and previously unavailable
        servers to be added.
        """
        kerberos_uris = discover_kdc_domain_controllers_in_domain(self.domain, site=self.site,
                                                                  dns_nameservers=self.dns_nameservers,
                                                                  source_ip=self.source_ip)
        self.set_kerberos_uris(kerberos_uris)

    def _create_connection(self, user, password, authentication_mechanism, **kwargs):
        """ Internal helper for creating sessions regardless of whether they're for users or computers """
        if len(self.ldap_servers) == 0:
            raise DomainConnectException('Cannot create a session with the AD domain, as there are no LDAP servers '
                                         'known for the domain.')
        # our servers were either user specified (in which case it's a list of ordered preferences) or
        # were discovered automatically (in which case they're ordered by RTT), so use the FIRST strategy
        # to either contact the first preferred server or the fastest/closest server
        copied_servers = [self._copy_ldap_server(serv) for serv in self.ldap_servers]
        server_pool = ServerPool(servers=copied_servers, pool_strategy=FIRST)
        # if the authentication mechanism is a SASL mechanism, set the authentication mechanism to SASL
        # and move the current authentication mechanism to be the sasl_mechanism in the kwargs
        if kwargs.get('authentication_mechanism'):
            logger.debug('authentication_mechanism specified in both kwargs and args: %s and %s',
                         kwargs.pop('authentication_mechanism'), authentication_mechanism)
            logger.debug('Chose argument authentication_mechanism %s', authentication_mechanism)

        # ntlm isn't real SASL, but Kerberos, EXTERNAL, etc. are.
        if authentication_mechanism in SASL_AVAILABLE_MECHANISMS:
            kwargs['sasl_mechanism'] = authentication_mechanism
            authentication_mechanism = SASL

        # if no client strategy is specified, default to restartable. AD tends to close idle connections;
        # also if a user specified the LDAP servers, they may have used a hostname that has many servers
        # behind it (like just the domain name), which can cause connections to break if they're using TLS
        # an experience a dns failover on a synchronous connection. Restartable connections avoid these issues.
        # Use safe restartable in case the caller uses this in a multi-threaded application.
        client_strat = kwargs.pop('client_strategy', SAFE_RESTARTABLE)
        # users can use different source addresses for each session if they want. otherwise use the source ip
        # that was used in domain discovery
        source_addr = kwargs.pop('source_address', self.source_ip)
        conn = Connection(server_pool, user=user, password=password, authentication=authentication_mechanism,
                          client_strategy=client_strat, source_address=source_addr,
                          **kwargs)

        conn.open()
        logger.debug('Opened connection to AD domain %s: %s', self.domain, conn)
        if self.encrypt_connections:
            # if we're using LDAPS, don't StartTLS
            if not conn.server.ssl:
                tls_started = conn.start_tls()
                if not tls_started:
                    raise DomainConnectException('Unable to StartTLS on connection to domain. Please check the '
                                                 'server(s) to ensure that they have properly configured certificates.')
            logger.debug('Successfully secured connection to AD domain %s', self.domain)
        bind_resp = conn.bind()
        bound, result, _, _ = process_ldap3_conn_return_value(conn, bind_resp)
        if not bound:
            raise DomainConnectException('Failed to bind connection to {} - please check the credentials and '
                                         'authentication mechanism in use. LDAP result: {}'
                                         .format(conn.server.name, result))
        logger.debug('Successfully bound connection to AD domain %s to establish session', self.domain)
        return conn

    def create_ldap_connection_as_user(self, user: str = None, password: str = None,
                                       authentication_mechanism: str = None,
                                       **kwargs) -> Connection:
        """ Create an LDAP connection with AD domain authenticated as the specified user.

        :param user: The name of the user to use when authenticating with the domain. This should be formatted based
                     on the authentication mechanism. For example, kerberos authentication expects username@domain,
                     NTLM expects domain\\username, and simple authentication can use a distinguished name,
                     username@domain, or other formats based on your domain's settings.
                     If not specified, anonymous authentication will be used. If specified, SIMPLE authentication
                     will be used by default if authentication_mechanism is not specified.
        :param password: The password to use when authenticating with the domain.
                         If not specified, anonymous authentication will be used. If specified, SIMPLE authentication
                         will be used by default if authentication_mechanism is not specified.
        :param authentication_mechanism: An LDAP authentication mechanism or SASL mechanism. If 'SASL' is specified,
                                         then the keyword argument `sasl_mechanism` must also be specified. Valid values
                                         include all authentication mechanisms and SASL mechanisms from the ldap3
                                         library, such as SIMPLE, NTLM, KERBEROS, etc.
        :param kwargs: Additional keyword arguments can be specified for any of the arguments to an ldap3 Connection
                       object and they will be used. This can be used to set things like `client_strategy` or
                       `pool_name`.
        :return: An ldap3 Connection object representing a connection with the domain.
        """
        logger.info('Establishing connection with AD domain %s using LDAP authentication mechanism %s and user %s',
                    self.domain, authentication_mechanism, user)
        return self._create_connection(user, password, authentication_mechanism, **kwargs)

    def create_session_as_user(self, user: str = None, password: str = None, authentication_mechanism: str = None,
                               **kwargs) -> ADSession:
        """ Create a session with AD domain authenticated as the specified user.

        :param user: The name of the user to use when authenticating with the domain. This should be formatted based
                     on the authentication mechanism. For example, kerberos authentication expects username@domain,
                     NTLM expects domain\\username, and simple authentication can use a distinguished name,
                     username@domain, or other formats based on your domain's settings.
                     If not specified, anonymous authentication will be used. If specified, SIMPLE authentication
                     will be used by default if authentication_mechanism is not specified.
        :param password: The password to use when authenticating with the domain.
                         If not specified, anonymous authentication will be used. If specified, SIMPLE authentication
                             will be used by default if authentication_mechanism is not specified.
        :param authentication_mechanism: An LDAP authentication mechanism or SASL mechanism. If 'SASL' is specified,
                                         then the keyword argument `sasl_mechanism` must also be specified. Valid values
                                         include all authentication mechanisms and SASL mechanisms from the ldap3
                                         library, such as SIMPLE, NTLM, KERBEROS, etc.
        :param kwargs: Additional keyword arguments can be specified for any of the arguments to an ldap3 Connection
                       object and they will be used. This can be used to set things like `client_strategy` or
                       `pool_name`.
        :return: An ADSession object representing a connection with the domain.
        """
        logger.info('Establishing session with AD domain %s using LDAP authentication mechanism %s and user %s',
                    self.domain, authentication_mechanism, user)
        conn = self._create_connection(user, password, authentication_mechanism, **kwargs)
        session = ADSession(conn, self)
        return session

    def create_ldap_connection_as_computer(self, computer_name: str, computer_password: str = None,
                                           check_name_format: bool = True,
                                           authentication_mechanism: str = KERBEROS, **kwargs) -> Connection:
        """ Create an LDAP connection with AD domain authenticated as the specified computer.
        :param computer_name: The name of the computer to use when authenticating with the domain.
        :param computer_password: Optional, the password of the computer to use when authenticating with the domain.
                                  If using an authentication mechanism like NTLM, this must be specified. But for
                                  authentication mechanisms such as kerberos or external, either `sasl_credentials`
                                  can be specified as a keyword argument or default system credentials will be used
                                  in accordance with the auth mechanism.
        :param check_name_format: If True, the `computer_name` will be processed to try and format it based on the
                                  authentication mechanism in use. For NTLM we will try to format it as
                                  `domain`\\`computer_name`, and for Kerberos/GSSAPI we will try to format is ass
                                  `computer_name`@`domain`.
                                  Defaults to True.
        :param authentication_mechanism: An LDAP authentication mechanism or SASL mechanism. If 'SASL' is specified,
                                         then the keyword argument `sasl_mechanism` must also be specified. Valid values
                                         include all authentication mechanisms and SASL mechanisms from the ldap3
                                         library, such as SIMPLE, NTLM, KERBEROS, etc.
        :param kwargs: Additional keyword arguments can be specified for any of the arguments to an ldap3 Connection
                       object and they will be used. This can be used to set things like `client_strategy` or
                       `pool_name`.
        :returns: A Connection object representing a ldap connection with the domain.
        """
        logger.info(
            'Establishing LDAP connection with AD domain %s using LDAP authentication mechanism %s and computer %s',
            self.domain, authentication_mechanism, computer_name)
        # reject simple binds because computers can't use them for authentication
        if authentication_mechanism == SIMPLE or authentication_mechanism == ANONYMOUS:
            raise InvalidDomainParameterException('Computers must use a form of SASL or NTLM for authenticating LDAP '
                                                  'communication with and AD domain.')
        # when using EXTERNAL authentication (certificate-based) there might be some weird names, so let power users
        # skip our helpful name formatting/validation logic in case it causes issues
        formatted_name = computer_name
        if check_name_format:
            formatted_name = format_computer_name_for_authentication(computer_name, self.domain,
                                                                     authentication_mechanism)
        return self._create_connection(formatted_name, computer_password, authentication_mechanism, **kwargs)

    def create_session_as_computer(self, computer_name: str, computer_password: str = None,
                                   check_name_format: bool = True,
                                   authentication_mechanism: str = KERBEROS, **kwargs) -> ADSession:
        """ Create a session with AD domain authenticated as the specified computer.
        :param computer_name: The name of the computer to use when authenticating with the domain.
        :param computer_password: Optional, the password of the computer to use when authenticating with the domain.
                                  If using an authentication mechanism like NTLM, this must be specified. But for
                                  authentication mechanisms such as kerberos or external, either `sasl_credentials`
                                  can be specified as a keyword argument or default system credentials will be used
                                  in accordance with the auth mechanism.
        :param check_name_format: If True, the `computer_name` will be processed to try and format it based on the
                                  authentication mechanism in use. For NTLM we will try to format it as
                                  `domain`\\`computer_name`, and for Kerberos/GSSAPI we will try to format is ass
                                  `computer_name`@`domain`.
                                  Defaults to True.
        :param authentication_mechanism: An LDAP authentication mechanism or SASL mechanism. If 'SASL' is specified,
                                         then the keyword argument `sasl_mechanism` must also be specified. Valid values
                                         include all authentication mechanisms and SASL mechanisms from the ldap3
                                         library, such as SIMPLE, NTLM, KERBEROS, etc.
        :param kwargs: Additional keyword arguments can be specified for any of the arguments to an ldap3 Connection
                       object and they will be used. This can be used to set things like `client_strategy` or
                       `pool_name`.
        :returns: An ADSession object representing a connection with the domain.
        """
        logger.info('Establishing session with AD domain %s using LDAP authentication mechanism %s and computer %s',
                    self.domain, authentication_mechanism, computer_name)
        conn = self.create_ldap_connection_as_computer(computer_name, computer_password, check_name_format,
                                                       authentication_mechanism, **kwargs)
        session = ADSession(conn, self)
        return session

    def join(self, admin_username: str, admin_password: str, authentication_mechanism: str = SIMPLE,
             computer_name: str = None, computer_location: str = None, computer_password: str = None,
             computer_encryption_types: List[Union[str, ADEncryptionType]] = None, computer_hostnames: List[str] = None,
             computer_services: List[str] = None, supports_legacy_behavior: bool = False,
             computer_key_file_path: str = DEFAULT_KRB5_KEYTAB_FILE_LOCATION,
             **additional_account_attributes) -> ManagedADComputer:
        """ A super simple 'join the domain' function that requires minimal input - just admin user credentials
        to use in the join process.
        Given those basic inputs, the domain's settings are used to establish a connection, and an account is made
        with strong security settings. The account's attributes follow AD naming conventions based on the computer's
        hostname by default.
        :param admin_username: The username of a user or computer with the rights to create the computer.
                               This username should be formatted based on the authentication protocol being used.
                               For example, DOMAIN\\username for NTLM as opposed to username@DOMAIN for GSSAPI, or
                               a distinguished name for SIMPLE.
                               If `old_computer_password` is specified, then this account only needs permission to
                               change the password of the computer being taken over, which is different from the reset
                               password permission.
        :param admin_password: The password for the user. Optional, as SASL authentication mechanisms can use
                               `sasl_credentials` specified as a keyword argument, and things like KERBEROS will use
                               default system kerberos credentials if they're available.
        :param authentication_mechanism: An LDAP authentication mechanism or SASL mechanism. If 'SASL' is specified,
                                         then the keyword argument `sasl_mechanism` must also be specified. Valid values
                                         include all authentication mechanisms and SASL mechanisms from the ldap3
                                         library, such as SIMPLE, NTLM, KERBEROS, etc.
        :param computer_name: The name of the computer to take over in the domain. This should be the sAMAccountName
                              of the computer, though if computer has a trailing $ in its sAMAccountName and that is
                              omitted, that's ok. If not specified, we will attempt to find a computer with a name
                              matching the local system's hostname.
        :param computer_location: The location in which to create the computer. This may be specified as an LDAP-style
                                  relative distinguished name (e.g. OU=ServiceMachines,OU=Machines) or a windows path
                                  style canonical name (e.g. example.com/Machines/ServiceMachines).
                                  If not specified, defaults to CN=Computers which is the standard default for AD.
        :param computer_password: The password to set for the computer when taking it over. If not specified, a random
                                  120 character password will be generated and set.
        :param computer_encryption_types: A list of encryption types, based on the ADEncryptionType enum, to enable on
                                          the account created. These may be strings or enums; if they are strings,
                                          they should be strings of the encryption types as written in kerberos
                                          RFCs or in AD management tools, and we will try to map them to enums and
                                          raise an error if they don't match any supported values.
                                          AES256-SHA1, AES128-SHA1, and RC4-HMAC encryption types are supported. DES
                                          encryption types aren not.
                                          If not specified, defaults to [AES256-SHA1].
        :param computer_hostnames: Hostnames to set for the computer. These will be used to set the dns hostname
                                   attribute in AD. If not specified, the computer hostnames will default to
                                   [`computer_name`, `computer_name`.`domain`] which is the AD standard default.
        :param computer_services: Services to enable on the computers hostnames. These services dictate what clients
                                  can get kerberos tickets for when communicating with this computer, and this property
                                  is used with `computer_hostnames` to set the service principal names for the computer.
                                  For example, having `nfs` specified as a service principal is necessary if you want
                                  to run an NFS server on this computer and have clients get kerberos tickets for
                                  mounting shares; having `ssh` specified as a service principal is necessary for
                                  clients to request kerberos tickets for sshing to the computer.
                                  If not specified, defaults to `HOST` which is the standard AD default service.
                                  `HOST` covers a wide variety of services, including `cifs`, `ssh`, and many others
                                  depending on your domain. Determining exactly what services are covered by `HOST`
                                  in your domain requires checking the aliases set on a domain controller.
        :param supports_legacy_behavior: If `True`, then an error will be raised if the computer name is longer than
                                         15 characters (not including the trailing $). This is because various older
                                         systems such as NTLM, certain UNC path applications, Netbios, etc. cannot
                                         use names longer than 15 characters. This name cannot be changed after
                                         creation, so this is important to control at creation time.
                                         If not specified, defaults to `False`.
        :param computer_key_file_path: The path of where to write the keytab file for the computer after taking it over.
                                       This will include keys for both user and server keys for the computer.
                                       If not specified, defaults to /etc/krb5.keytab
        :param additional_account_attributes: Additional keyword argument can be specified to set other LDAP attributes
                                              of the computer that are not covered above, or where the above controls
                                              are not sufficiently granular. For example, `userAccountControl` could
                                              be used to set the user account control values for the computer if it's
                                              desired to set it differently from the default (e.g. create a computer
                                              in a disabled state and enable it later).
        :returns: A ManagedADComputer object representing the computer created.
        """
        ad_session = self.create_session_as_user(admin_username, admin_password, authentication_mechanism)
        return join_ad_domain_using_session(ad_session, computer_name=computer_name,
                                            computer_location=computer_location,
                                            computer_password=computer_password, computer_hostnames=computer_hostnames,
                                            computer_services=computer_services,
                                            computer_encryption_types=computer_encryption_types,
                                            supports_legacy_behavior=supports_legacy_behavior,
                                            computer_key_file_path=computer_key_file_path,
                                            **additional_account_attributes)

    def join_by_taking_over_existing_computer(self, admin_username: str, admin_password: str = None,
                                              authentication_mechanism: str = SIMPLE, computer_name: str = None,
                                              computer_password: str = None, old_computer_password: str = None,
                                              computer_key_file_path: str = DEFAULT_KRB5_KEYTAB_FILE_LOCATION,
                                              **additional_connection_attributes) -> ManagedADComputer:
        """ A super simple 'join the domain' function that requires minimal input - just admin user credentials
        to use in the join process.
        Given those basic inputs, the domain's settings are used to establish a connection, and an account is taken over
        based on inputs. The account's attributes are then read and used to generate kerberos keys and set other attributes
        of the returned object.
        :param admin_username: The username of a user or computer with the rights to reset the password of the computer
                               being taken over.
                               This username should be formatted based on the authentication protocol being used.
                               For example, DOMAIN\\username for NTLM as opposed to username@DOMAIN for GSSAPI, or
                               a distinguished name for SIMPLE.
                               If `old_computer_password` is specified, then this account only needs permission to
                               change the password of the computer being taken over, which is different from the reset
                               password permission.
        :param admin_password: The password for the user. Optional, as SASL authentication mechanisms can use
                               `sasl_credentials` specified as a keyword argument, and things like KERBEROS will use
                               default system kerberos credentials if they're available.
        :param authentication_mechanism: An LDAP authentication mechanism or SASL mechanism. If 'SASL' is specified,
                                         then the keyword argument `sasl_mechanism` must also be specified. Valid values
                                         include all authentication mechanisms and SASL mechanisms from the ldap3
                                         library, such as SIMPLE, NTLM, KERBEROS, etc.
        :param computer_name: The name of the computer to take over in the domain. This should be the sAMAccountName
                              of the computer, though if computer has a trailing $ in its sAMAccountName and that is
                              omitted, that's ok. If not specified, we will attempt to find a computer with a name
                              matching the local system's hostname.
        :param computer_password: The password to set for the computer when taking it over. If not specified, a random
                                  120 character password will be generated and set.
        :param old_computer_password: The current password of the computer being taken over. If specified, the action
                                      of taking over the computer will use a "change password" operation, which is less
                                      privileged than a "reset password" operation. So specifying this reduces the
                                      permissions needed by the user specified.
        :param computer_key_file_path: The path of where to write the keytab file for the computer after taking it over.
                                       This will include keys for both user and server keys for the computer.
                                       If not specified, defaults to /etc/krb5.keytab
        :param additional_connection_attributes: Additional keyword arguments may be specified for any properties of
                                                 the `Connection` object from the `ldap3` library that is desired to
                                                 be set on the connection used in the session created for taking over
                                                 the computer. Examples include `sasl_credentials`, `client_strategy`,
                                                 `cred_store`, and `pool_lifetime`.
        :returns: A ManagedADComputer object representing the computer taken over.
        """
        ad_session = self.create_session_as_user(admin_username, admin_password, authentication_mechanism,
                                                 **additional_connection_attributes)
        return join_ad_domain_by_taking_over_existing_computer_using_session(
            ad_session, computer_name=computer_name, computer_password=computer_password,
            old_computer_password=old_computer_password, computer_key_file_path=computer_key_file_path)

    def __repr__(self):
        result = 'ADDomain(domain={}'.format(self.domain)
        if self.site:
            result += ', site={}'.format(self.site)
        enc_connections = 'True' if self.encrypt_connections else 'False'
        result += ', encrypt_connections=' + enc_connections
        if self.ldap_servers:
            list_repr = ','.join(serv.__repr__() for serv in self.ldap_servers)
            result += ', ldap_servers_or_uris=[{}]'.format(list_repr)
        if self.kerberos_uris:
            list_repr = ','.join(serv.__repr__() for serv in self.kerberos_uris)
            result += ', kerberos_uris=[{}]'.format(list_repr)
        if self.ca_certificates_file_path:
            result += ', ca_certificates_file_path=' + self.ca_certificates_file_path
        if self.dns_nameservers:
            list_repr = ','.join(serv.__repr__() for serv in self.dns_nameservers)
            result += ', dns_nameservers=[{}]'.format(list_repr)
        if self.source_ip:
            result += ', source_ip=' + self.source_ip
        if self.netbios_name:
            result += ', netbios_name=' + self.netbios_name
        result += ')'

        return result

    def __str__(self):
        return self.__repr__()


class ADTrustedDomain:

    def __init__(self, primary_domain: ADDomain, trust_ldap_attributes: dict):
        """ ADTrustedDomain objects represent a trustedDomain object found within an ADDomain.

        :param primary_domain: An ADDomain object representing the domain where this trusted domain object was found.
        :param trust_ldap_attributes: A dictionary of LDAP attributes for the trustedDomain.
        """
        self.primary_domain = primary_domain
        self.domain = trust_ldap_attributes.get(AD_TRUSTED_DOMAIN_FQDN)
        self.netbios_name = trust_ldap_attributes.get(AD_TRUSTED_DOMAIN_NETBIOS_NAME)
        self.trust_type = trust_ldap_attributes.get(AD_TRUST_TYPE, 0)
        # parse our trust direction
        trust_dir = trust_ldap_attributes.get(AD_TRUST_DIRECTION, 0)
        self.disabled = trust_dir == trust_constants.TRUST_DIRECTION_DISABLED
        self.primary_domain_is_trusted_by_self = bool(trust_dir & trust_constants.TRUST_DIRECTION_INBOUND)
        self.self_is_trusted_by_primary_domain = bool(trust_dir & trust_constants.TRUST_DIRECTION_OUTBOUND)

        # other trust values
        self.trust_attributes_value = trust_ldap_attributes.get(AD_TRUST_ATTRIBUTES, 0)
        self.trust_posix_offset = trust_ldap_attributes.get(AD_TRUST_POSIX_OFFSET, 0)

        # keep our raw ldap attributes in case there's more we don't explicitly extract
        self.trust_ldap_attributes = trust_ldap_attributes

    def convert_to_ad_domain(self, site: str = None, ldap_servers_or_uris: List = None,
                             kerberos_uris: List[str] = None,
                             encrypt_connections: bool = True,
                             ca_certificates_file_path: str = None,
                             discover_ldap_servers: bool = True,
                             discover_kerberos_servers: bool = True,
                             dns_nameservers: List[str] = None,
                             source_ip: str = None) -> ADDomain:
        """Convert this AD domain trust to an ADDomain object. This takes all of the same keyword arguments
        as creating an ADDomain object, and use the attributes of the primary domain where appropriate for
        network settings.

        :param site: The Active Directory site to operate within. This is only relevant if LDAP or
                     kerberos servers are discovered in DNS, as there's site-specific records.
                     If set, only hosts within the specified site will be used.
        :param ldap_servers_or_uris: A list of either Server objects from the ldap3 library, or
                                     string LDAP uris. If specified, they will be used to establish
                                     sessions with the domain.
        :param kerberos_uris: A list of string kerberos server uris. These can be IPs (and the default
                              kerberos port of 88 will be used) or IP:port combinations.
        :param encrypt_connections: Whether or not LDAP connections with the domain will be secured
                                    using TLS. This must be True for join functionality to work,
                                    as passwords can only be set over secure connections.
                                    If not specified, defaults to True. If LDAP server objects are
                                    provided with ssl enabled or ldaps:// uris are provided, then
                                    connections to those servers will be encrypted because of the
                                    inherent behavior of such configurations.
        :param ca_certificates_file_path: A path to CA certificates to be used to establish trust
                                          with LDAP servers when securing connections. If not
                                          specified, then TLS will not check the peer certificate.
                                          If LDAP server objects are specified, then their TLS
                                          settings will be used rather than anything set in this
                                          variable. It is only used when discovering servers or
                                          using string URIs, so Server objects can be used if
                                          different CAs sign different servers' certificates
                                          due to regional CAs or something similar.
                                          If not specified, defaults to None.
        :param discover_ldap_servers: If true, and LDAP servers/uris are not specified, then LDAP
                                      servers for the domain will be discovered in DNS.
                                      If not specified, defaults to True.
        :param discover_kerberos_servers: If true, and kerberos uris are not specified, then kerberos
                                          servers for the domain will be discovered in DNS.
                                          If not specified, defaults to True.
        :param dns_nameservers: A list of strings indicating the IP addresses of DNS servers to use
                                when discovering servers for the domain. These may be IPv4 or IPv6
                                addresses.
                                If not specified, defaults to the DNS nameservers configured in the
                                primary domain where this trusted domain was found because domains
                                that trust each other are mutually discoverable in each others'
                                DNS or must use a DNS that contains both of them.
                                If not specified and the primary domain has no nameservers set,
                                defaults to what's configured in /etc/resolv.conf on POSIX systems,
                                and extracting nameservers from registry keys on windows.
                                Can be set to an empty list to force use of the system defaults even
                                when the primary domain has dns_nameservers set.
        :param source_ip: A source IP address to use for both DNS and LDAP connections established for
                          this domain.
                          If not specified, defaults to the source IP used for the primary where
                          this trusted domain was found, because domains that trust each other are
                          mutually routable, and so the source IP used to talk to the primary domain
                          is assumed to also be the right default network identity for talking to
                          this domain.
                          If not specified and the primary domain has no source ip set, defaults to
                          automatic assignment of IP using underlying system networking.
                          Can be set to an empty string to force use of the system defaults even
                          when the primary domain has source_ip set.
        :returns: An ADDomain object representing this trusted domain as a complete domain with the
                  corresponding functionality.
        """
        if not self.is_active_directory_domain_trust():
            raise TrustedDomainConversionException('Cannot convert a non-AD trusted domain to an ADDomain object.')

        logger.info('Creating ADDomain object for %s which is a trusted domain found in %s',
                    self.domain, self.primary_domain.domain)
        if dns_nameservers is None and self.primary_domain.dns_nameservers:
            logger.info('Using DNS nameservers from primary domain %s for new ADDomain, because domains with a '
                        'trust relationship must be mutually routable', self.primary_domain.domain)
            dns_nameservers = self.primary_domain.dns_nameservers

        if source_ip is None and self.primary_domain.source_ip:
            logger.info('Using source IP address from primary domain %s for new ADDomain, because domains with a '
                        'trust relationship must be mutually routable, meaning we should communicate over the same '
                        'network when connecting to the new ADDomain', self.primary_domain.domain)
            source_ip = self.primary_domain.source_ip

        return ADDomain(self.domain, site=site, ldap_servers_or_uris=ldap_servers_or_uris,
                        kerberos_uris=kerberos_uris, encrypt_connections=encrypt_connections,
                        ca_certificates_file_path=ca_certificates_file_path,
                        discover_ldap_servers=discover_ldap_servers,
                        discover_kerberos_servers=discover_kerberos_servers,
                        dns_nameservers=dns_nameservers, source_ip=source_ip,
                        netbios_name=self.netbios_name)

    def get_fqdn(self) -> str:
        """ Returns the FQDN of the trusted domain. """
        return self.domain

    def get_netbios_name(self) -> str:
        """ Returns the netbios name of the trusted domain. """
        return self.netbios_name

    def get_posix_offset(self) -> int:
        """ Returns the posix offset for the trust relationship. This is specific to the primary domain. """
        return self.trust_posix_offset

    def get_raw_trust_attributes_value(self) -> int:
        """ Returns the raw trust attributes value, which is a bitstring indicating properties of the trust. """
        return self.trust_attributes_value

    # trust types

    def is_non_active_directory_windows_trust(self) -> bool:
        """ Returns True if the trusted domain is a non-Active Directory windows domain. """
        return self.trust_type == trust_constants.TRUST_TYPE_NON_AD_WINDOWS

    def is_active_directory_domain_trust(self) -> bool:
        """ Returns True if the trusted domain is an Active Directory domain. """
        return self.trust_type == trust_constants.TRUST_TYPE_WINDOWS_AD

    def is_mit_trust(self) -> bool:
        """ Returns True if the trusted domain is an MIT Kerberos Realm. """
        return self.trust_type == trust_constants.TRUST_TYPE_MIT

    # trust directions

    def is_disabled(self) -> bool:
        """ Returns True if the trust relationship has been disabled. """
        return self.disabled

    def is_bidirectional_trust(self) -> bool:
        """ Returns True if the trust is mutual, meaning the primary domain trusts users from the trusted domain, and
        the trusted domain trusts users from the primary domain."""
        return self.primary_domain_is_trusted_by_self and self.self_is_trusted_by_primary_domain

    def trusts_primary_domain(self) -> bool:
        """ Returns True if the trusted domain trusts users originating in the primary domain. """
        return self.primary_domain_is_trusted_by_self

    def is_trusted_by_primary_domain(self) -> bool:
        """ Returns True if the primary domain trusts users originating in the trusted domain. """
        return self.self_is_trusted_by_primary_domain

    # trust attributes

    def is_transitive_trust(self) -> bool:
        """ Returns True if the trust relationship is transitive. If a relationship is transitive, then that means
        that if A trusts principals from B, and B trusts principals from C, then A will also trust principals from C
        even if it doesn't explicitly know that C exists.
        Cross-forest trusts are inherently transitive unless transitivity is disabled. Cross-domain trusts are not
        inherently transitive.
        """
        inherently_transitive = self.is_cross_forest_trust()
        explicitly_non_transitive = bool(
            self.trust_attributes_value & trust_constants.TRUST_ATTRIBUTE_NON_TRANSITIVE_BIT)
        return inherently_transitive and not explicitly_non_transitive

    def is_cross_forest_trust(self) -> bool:
        """ Returns True if the trust relationship is a cross-forest trust. """
        return bool(self.trust_attributes_value & trust_constants.TRUST_ATTRIBUTE_FOREST_TRANSITIVE_BIT)

    def is_cross_organization_trust(self) -> bool:
        """ Returns True if the trust relationship is a cross-organization trust. """
        return bool(self.trust_attributes_value & trust_constants.TRUST_ATTRIBUTE_CROSS_ORGANIZATION_BIT)

    def is_in_same_forest_as_primary_domain(self) -> bool:
        """ Returns True if the trusted domain is in the same forest as the primary domain. For example,
        both "americas.my-corp.net" and "emea.my-corp.net" might be subdomains within the "my-corp.net"
        forest.
        """
        return bool(self.trust_attributes_value & trust_constants.TRUST_ATTRIBUTE_WITHIN_FOREST)

    def is_findable_via_netlogon(self) -> bool:
        """ Returns True if the trusted domain is findable in netlogon and the trust works there. """
        # things that are do not support pre-windows 2000 do not appear in netlogon.
        # and as far as I can tell, that's the only meaningful information in this bit
        return not (self.trust_attributes_value & trust_constants.TRUST_ATTRIBUTE_WIN_2000_PLUS_ONLY_BIT)

    def should_treat_as_external_trust(self) -> bool:
        """ Returns True if the trusted domain is configured such that it should be explicitly treated as
        if the trusted domain is external to the forest of the primary domain, despite being within it.
        """
        return bool(self.trust_attributes_value & trust_constants.TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL)

    def mit_trust_uses_rc4_hmac_for(self) -> bool:
        """ Returns True to indicate that this trusted MIT Kerberos Realm can use RC4-HMAC encryption.
        This is only relevant for MIT Kerberos Realms, and is a legacy attribute from a time when
        RC4-HMAC was not widely adopted, AES128/AES256 weren't standard in AD, and only the less secure
        single-DES encryption mechanisms were shared between MIT and AD by default.
        """
        return bool(self.trust_attributes_value & trust_constants.TRUST_ATTRIBUTE_USES_RC4_ENCRYPTION)

    def uses_sid_filtering(self) -> bool:
        """ Returns True if this relationship employs SID filtering. This is common in forest trusts/transitive trusts
        in order to ensure some level of control over which users from other domains are allowed to operate within
        the primary domain.
        """
        return bool(self.trust_attributes_value & trust_constants.TRUST_ATTRIBUTE_QUARANTINED_DOMAIN_BIT)

    def create_transfer_session_to_trusted_domain(self, ad_session: ADSession, converted_ad_domain: ADDomain = None,
                                                  skip_validation: bool = False) -> ADSession:
        """ Create a session with this trusted domain that functionally transfers the authentication of a given session.
        This is useful for transferring a kerberos/ntlm session to create new sessions for querying in trusted domains
        without needing to provide credentials ever time.

        :param ad_session: The active directory session to transfer. This session will not be altered.
        :param converted_ad_domain: Optional. If a caller wants to specify information like an AD site, or ldap
                                    server preferences, or if the caller simply wants to avoid having DNS lookups
                                    and RTT measurements done every single time they transfer a session because they
                                    have a lot of sessions to transfer, then they can specify an ADDomain object
                                    that represents the converted ADTrustedDomain.
                                    If not specified, an ADDomain will be created for the trusted domain during
                                    transfer.
        :param skip_validation: Optional. If set to False, validation checks about the trusted domain being an AD domain
                                or the trusted domain trusting the primary domain for users originating from the
                                primary domain will be skipped. This can be set to True in scenarios where the trust
                                has been reconfigured on the trusted domain, but the primary domain has stale info,
                                to avoid needing to wait for changes to propagate to make use of the new trust.
                                If not specified, defaults to True.
        :returns: An ADSession representing the transferred authentication to the trusted domain.
        :raises: SessionTransferException If any validation fails when transferring the session.
        :raises: Other LDAP exceptions if the attempt to bind the transfer session in the trusted domain fails due to
                 authentication issues (e.g. trying to use a non-transitive trust when transferring a user that is
                 not from the primary domain, transferring across a one-way trust when skipping validation,
                 transferring to a domain using SID filtering to restrict cross-domain users)
        """
        if skip_validation:
            logger.info('Skipping validation when transferring session from %s to trusted domain %s',
                        self.primary_domain.get_domain_dns_name(), self.domain)

        # SIMPLE authentication can't transfer between trusts. this validation cannot be skipped.
        if ad_session.get_ldap_connection().authentication == SIMPLE:
            raise SessionTransferException('Active Directory sessions using SIMPLE authentication cannot be '
                                           'transferred to trusted domains. Either NTLM or some form of SASL (e.g. '
                                           'Kerberos) must be used.')

        # only transfer to AD domain trusts
        if (not skip_validation) and not self.is_active_directory_domain_trust():
            raise SessionTransferException('Active Directory sessions can only be transferred to Active Directory '
                                           'domain trusts. MIT trusts and non-AD windows trusts are not supported.')
        session_user_from_primary_domain = ad_session.is_session_user_from_domain()
        # if the user is from the primary domain, but the trust is one way and the primary domain's users aren't
        # trusted by this domain, raise an exception
        if (not skip_validation) and session_user_from_primary_domain and (not self.primary_domain_is_trusted_by_self):
            session_user = ad_session.who_am_i()
            raise SessionTransferException('The session user {} is a member of primary domain {} - but the trusted '
                                           'domain {} does not trust the primary domain, and so sessions cannot be '
                                           'transferred to it.'.format(session_user,
                                                                       self.primary_domain.get_domain_dns_name(),
                                                                       self.domain))

        session_user_from_this_domain = ad_session.find_netbios_name_for_domain() == self.netbios_name
        # if the user is not from the trusted domain or the primary domain, and the trust is not transitive,
        # log a warning. we won't fail this because the trusted domain could have an explicit trust relationship
        # with the primary domain. but there's a decent chance we'll fail here if the current session user is
        # attempting to authenticate with the trusted domain via implicit trust to the primary domain
        if ((not skip_validation) and (not session_user_from_this_domain)
                and (not session_user_from_primary_domain) and (not self.is_transitive_trust())):
            session_user = ad_session.who_am_i()
            logger.warning('Attempting to transfer authentication for user %s from domain %s to trusted domain %s - '
                           'however, the user does not belong to either domain and the trust is not transitive. So '
                           'this transfer is likely to fail unless the trusted domain has an explicit trust '
                           'relationship with the original domain of the user', session_user,
                           self.primary_domain.get_domain_dns_name(), self.domain)

        # if we didn't get a converted AD domain passed in, then just make one now. we support passing one in
        # so that users can convert the trust themselves and set information like site and server preferences,
        # and cut down on dns discovery costs if they'll transfer a lot of sessions
        if converted_ad_domain is None:
            logger.info('Creating new converted AD domain from trusted domain for %s', self.domain)
            converted_ad_domain = self.convert_to_ad_domain()

        session_conn = ad_session.get_ldap_connection()

        # copy the connection using all relevant attributes.
        # if ldap3 adds more things, this may need to become versioned and have new things added to it.
        # we may also support old ldap3 versions if there's high demand and if I'm feeling particularly
        # generous, so if that happens we may also need to version this.
        return converted_ad_domain.create_session_as_user(session_conn.user, session_conn.password,
                                                          authentication_mechanism=session_conn.authentication,
                                                          auto_encode=session_conn.auto_encode,
                                                          auto_escape=session_conn.auto_escape,
                                                          auto_referrals=session_conn.auto_referrals,
                                                          check_names=session_conn.check_names,
                                                          client_strategy=session_conn.strategy_type,
                                                          cred_store=session_conn.cred_store,
                                                          fast_decoder=session_conn.fast_decoder,
                                                          lazy=session_conn.lazy,
                                                          pool_keepalive=session_conn.pool_keepalive,
                                                          pool_lifetime=session_conn.pool_lifetime,
                                                          pool_name=session_conn.pool_name,
                                                          pool_size=session_conn.pool_size,
                                                          raise_exceptions=session_conn.raise_exceptions,
                                                          read_only=session_conn.read_only,
                                                          receive_timeout=session_conn.receive_timeout,
                                                          return_empty_attributes=session_conn.empty_attributes,
                                                          sasl_mechanism=session_conn.sasl_mechanism,
                                                          sasl_credentials=session_conn.sasl_credentials,
                                                          source_address=session_conn.source_address,
                                                          source_port_list=session_conn.source_port_list,
                                                          use_referral_cache=session_conn.use_referral_cache)

    def __repr__(self):
        return ('ADTrustedDomain(primary_domain={}, trust_ldap_attributes={})'
                .format(self.primary_domain.__repr__(), self.trust_ldap_attributes))

    def __str__(self):
        return self.__repr__()
