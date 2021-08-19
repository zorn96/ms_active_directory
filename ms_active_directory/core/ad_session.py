import copy
import socket
import ssl

from ms_active_directory import logging_utils

from ldap3 import (
    BASE,
    Connection,
    SUBTREE,
)
from typing import List

import ms_active_directory.environment.constants as constants
import ms_active_directory.environment.ldap.ldap_format_utils as ldap_utils
import ms_active_directory.environment.ldap.ldap_constants as ldap_constants
import ms_active_directory.environment.security.security_config_utils as security_utils
import ms_active_directory.environment.security.security_config_constants as security_constants

from ms_active_directory.core.ad_computer import ADComputer
from ms_active_directory.core.ad_users_and_groups import ADGroup, ADUser
from ms_active_directory.exceptions import (
    ObjectCreationException,
    DomainSearchException
)

logger = logging_utils.get_logger()


class ADSession:

    def __init__(self, ldap_connection: Connection, domain):
        self.ldap_connection = ldap_connection
        self.domain = domain
        self.domain_dns_name = self.domain.get_domain_dns_name()
        self.domain_search_base = ldap_utils.construct_ldap_base_dn_from_domain(self.domain_dns_name)

    def is_authenticated(self):
        """ Returns if the session is currently authenticated """
        return self.ldap_connection.bound

    def is_encrypted(self):
        """ Returns if the session's connection is encrypted """
        return self.ldap_connection.tls_started or self.ldap_connection.server.ssl

    def is_open(self):
        """ Returns if the session's connection is currently open """
        return not self.ldap_connection.closed

    def is_thread_safe(self):
        """ Returns if the session's connection is thread-safe """
        return self.ldap_connection.strategy.thread_safe

    def get_ldap_connection(self):
        """ Returns the LDAP connection that this session uses for communication.
        This is particularly useful if a user wants to make complex LDAP queries or perform
        operations that are not supported by the ADSession object, and is willing to craft
        them and parse results themselves.
        """
        return self.ldap_connection

    def get_current_server_uri(self):
        """ Returns the URI of the server that this session is currently communicating with """
        return self.ldap_connection.server.name

    def get_domain(self):
        """ Returns the domain that this session is connected to """
        return self.domain

    def get_domain_dns_name(self):
        """ Returns the domain that this session is connected to """
        return self.domain_dns_name

    def dn_exists_in_domain(self, distinguished_name: str):
        """ Check if a distinguished name exists within the domain, regardless of what it is.
        :param distinguished_name: Either a relative distinguished name or full distinguished name
                                   to search for within the domain.
        :returns: True if the distinguished name exists within the domain.
        """
        # since the distinguished name may be a relative distinguished name or complete one,
        # normalize it
        normalized_rdn = ldap_utils.normalize_object_location_in_domain(distinguished_name,
                                                                        self.domain_dns_name)
        search_dn = normalized_rdn + ',' + self.domain_search_base
        # search returns True if it finds anything. we only need to find one object before stopping
        res = self.ldap_connection.search(search_base=search_dn,
                                          search_filter=ldap_constants.FIND_ANYTHING_FILTER,
                                          search_scope=BASE,
                                          size_limit=1)
        exists, _, _, _ = ldap_utils.process_ldap3_conn_return_value(self.ldap_connection, res)
        return exists

    def object_exists_in_domain_with_attribute(self, attr: str, unescaped_value: str):
        """ Check if any objects exist in the domain with a given attribute. Returns True if so, False otherwise.
        :param attr: The LDAP attribute to examine in the search.
        :param unescaped_value: The value of the attribute that we're looking for, in its raw form.
        :returns: True if any objects exist in the domain with the attribute specified equal to the value.
        """
        if ldap_utils.is_dn(unescaped_value):
            value = ldap_utils.escape_dn_for_filter(unescaped_value)
            logger.debug('Escaped value %s of %s as distinguished name to be %s', unescaped_value, attr, value)
        else:
            value = ldap_utils.escape_generic_filter_value(unescaped_value)
            logger.debug('Escaped value %s of %s as generic LDAP value to be %s', unescaped_value, attr, value)
        ldap_filter = '({}={})'.format(attr, value)
        # search returns True if it finds anything. we only need to find one object before stopping
        res = self.ldap_connection.search(search_base=self.domain_search_base,
                                          search_filter=ldap_filter,
                                          search_scope=SUBTREE,
                                          attributes=[attr],
                                          size_limit=1)
        _, _, response, _ = ldap_utils.process_ldap3_conn_return_value(self.ldap_connection, res)
        real_entities = ldap_utils.remove_ad_search_refs(response)
        return len(real_entities) > 0

    def _create_object(self, object_dn: str, object_classes: List[str], account_attr_dict: dict):
        if self.dn_exists_in_domain(object_dn):
            raise ObjectCreationException('An object already exists within the domain with distinguished name {} - '
                                          'please remove it or change the attributes specified such that a different '
                                          'distinguished name is created.'.format(object_dn))
        res = self.ldap_connection.add(object_dn, object_classes, account_attr_dict)
        # TODO: returning the actual response is probably a good idea so we can do something with it.
        # doing more with it in case of error would be a good idea too
        success, result, _, _ = ldap_utils.process_ldap3_conn_return_value(self.ldap_connection, res)
        if success:
            return success
        # don't include attributes in the exception because a password could be there and it could get logged.
        raise ObjectCreationException('An exception was encountered creating an object with distinguished name {} '
                                      'and object classes {}. LDAP result: {}'.format(object_dn, object_classes, result))

    def create_computer(self, computer_name: str, computer_location: str=None, computer_password: str=None,
                        encryption_types: List[security_constants.ADEncryptionType]=None, hostnames: List[str]=None,
                        services: List[str]=None, supports_legacy_behavior: bool=False,
                        **additional_account_attributes):
        """ Use the session to create a computer in the domain and return a computer object.
        :param computer_name: The common name of the computer to create in the AD domain. This
                              will be used to determine the sAMAccountName, and if no hostnames
                              are specified then this will be used to determine the hostnames for
                              the computer.
        :param computer_location: The distinguished name of the location within the domain where
                                  the computer will be created. It may be a relative distinguished
                                  name (not including the domain component) or a full distinguished
                                  name.  If not specified, defaults to CN=Computers which is
                                  standard for Active Directory.
        :param computer_password: The password to be set for the computer. This is particularly
                                  useful to specify if the computer will be shared across multiple
                                  applications or devices, or if pre-creating a computer for another
                                  application to use. If not specified, a random 120 character
                                  password will be generated.
        :param encryption_types: The encryption types to set as supported on the computer in AD.
                                 These will also be used to generate kerberos keys for the computer.
                                 If not specified, defaults to [aes256-cts-hmac-sha1-96].
        :param hostnames: The hostnames to use for configuring the service principal names of the
                          computer. These may be short hostnames or fully qualified domain names.
                          If not specified, defaults to the "computer_name" as a short hostname and
                          "computer_name.domain" as a fully qualified domain name.
        :param services: The services to enable on each hostname, which will be used with hostnames
                         to generate the computer's service principal names. If not specified,
                         defaults to ["HOST"] which is standard for Active Directory.
        :param supports_legacy_behavior: Does the computer being created support legacy behavior such
                                         as NTLM authentication or UNC path addressing from older windows
                                         clients? Defaults to False. Impacts the restrictions on
                                         computer naming.
        :param additional_account_attributes: Additional LDAP attributes to set on the account and their
                                              values. This is used to support power users setting arbitrary
                                              attributes, such as "userCertificate" to set the certificate
                                              for a computer that will use mutual TLS for EXTERNAL SASL auth.
                                              This also allows overriding of some values that are not explicit
                                              keyword arguments in order to avoid overcomplication, since most
                                              people won't set them (e.g. userAccountControl).
        """
        logger.debug('Request to create computer in domain %s with the following attributes: computer_name=%s, '
                     'computer_location=%s encryption_types=%s hostnames=%s services=%s supports_legacy_behavior=%s '
                     'number of additional attributes specified: %s', self.domain_dns_name, computer_name,
                     computer_location, encryption_types, hostnames, services, supports_legacy_behavior,
                     len(additional_account_attributes))
        # validate our computer name and then determine our sAMAccountName
        computer_name = ldap_utils.validate_and_normalize_computer_name(computer_name, supports_legacy_behavior)
        samaccount_name = computer_name + '$'

        if self.object_exists_in_domain_with_attribute(ldap_constants.AD_ATTRIBUTE_SAMACCOUNT_NAME, samaccount_name):
            raise ObjectCreationException('An object already exists with sAMAccountName {} so a computer may not be '
                                          'created with the name {}'.format(samaccount_name, computer_name))

        # get or normalize our computer location. the end format is as a relative distinguished name
        if computer_location is None:
            computer_location = ldap_constants.DEFAULT_COMPUTER_LOCATION
        else:
            computer_location = ldap_utils.normalize_object_location_in_domain(computer_location,
                                                                               self.domain_dns_name)
        if not self.dn_exists_in_domain(computer_location):
            raise ObjectCreationException('The computer location {} cannot be found in the domain.'
                                          .format(computer_location))
        # now we can build our full object distinguished name
        computer_dn = ldap_utils.construct_object_distinguished_name(computer_name, computer_location,
                                                                     self.domain_dns_name)
        if self.dn_exists_in_domain(computer_dn):
            raise ObjectCreationException('There exists an object in the domain with distinguished name {} and so a '
                                          'computer may not be created in the domain with name {} in location {}. '
                                          'Please use a different name or location.'
                                          .format(computer_dn, computer_name, computer_location))

        # generate a password if needed and encode it
        if computer_password is None:
            computer_password = security_utils.generate_random_ad_password()
        encoded_pw = security_utils.encode_password(computer_password)

        # normalize encryption type values and convert it to the encoded bitstring
        if encryption_types is None:
            encryption_types = [security_constants.ADEncryptionType.AES256_CTS_HMAC_SHA1_96]
        else:
            encryption_types = security_utils.normalize_encryption_type_list(encryption_types)
        encoded_enc_type_value = security_utils.get_supported_encryption_types_value(encryption_types)

        if hostnames is None:
            hostnames = ldap_utils.construct_default_hostnames_for_computer(computer_name, self.domain_dns_name)
        if services is None:
            services = ldap_constants.DEFAULT_COMPUTER_SERVICES
        spns = ldap_utils.construct_service_principal_names(services, hostnames)
        for spn in spns:
            if self.object_exists_in_domain_with_attribute(ldap_constants.AD_ATTRIBUTE_SERVICE_PRINCIPAL_NAMES, spn):
                raise ObjectCreationException('An object exists in the domain with service principal name {} and so '
                                              'creating a computer with the hostnames ({}) and services ({}) in use '
                                              'will cause undefined, conflicting behavior during lookups. Please '
                                              'specify different hostnames or services, or a different computer name '
                                              'if hostnames are not being explicitly set.'
                                              .format(spn, ', '.join(hostnames), ', '.join(services)))

        computer_attributes = {
            ldap_constants.AD_ATTRIBUTE_USER_ACCOUNT_CONTROL: ldap_constants.COMPUTER_ACCESS_CONTROL_VAL,
            ldap_constants.AD_ATTRIBUTE_PASSWORD: encoded_pw,
            ldap_constants.AD_ATTRIBUTE_SAMACCOUNT_NAME: samaccount_name,
            ldap_constants.AD_ATTRIBUTE_ENCRYPTION_TYPES: encoded_enc_type_value,
            ldap_constants.AD_ATTRIBUTE_SERVICE_PRINCIPAL_NAMES: spns,
            ldap_constants.AD_ATTRIBUTE_DNS_HOST_NAME: hostnames[0],
        }
        if len(hostnames) > 1:
            computer_attributes[ldap_constants.AD_ATTRIBUTE_ADDITIONAL_DNS_HOST_NAME] = hostnames[1:]
        # don't include additional attributes for logging in case they're sensitive
        loggable_attributes = copy.deepcopy(computer_attributes)
        del loggable_attributes[ldap_constants.AD_ATTRIBUTE_PASSWORD]
        logger.info('Attempting to create computer in domain %s with the following LDAP attributes: %s and %s additional attributes',
                    loggable_attributes, len(additional_account_attributes))

        # add in our additional account attributes at the end so they can override anything we set here
        computer_attributes.update(additional_account_attributes)

        self._create_object(computer_dn, ldap_constants.OBJECT_CLASSES_FOR_COMPUTER, computer_attributes)
        return ADComputer(samaccount_name, self.domain, computer_location, computer_password, spns,
                          encryption_types)

    def take_over_existing_computer(self, computer_name: str):
        """ Use the session to take over a computer in the domain and return a computer object.
        This resets the computer's password so that nobody else can impersonate it, and reads
        the computer's attributes in order to create a computer object and return it.
        :param computer_name: The common name or sAMAccountName of the computer to find in the AD domain.
                              If it appears to be a common name, not ending in $, a sAMAccountName will
                              be derived to search for. If that cannot be found, then a search will be
                              done for this as a common name. If no unique computer can be found with that
                              search, then an exception will be raised.
        """
        raise NotImplementedError()

    def is_domain_close_in_time_to_localhost(self, allowed_drift_seconds=None):
        """ Get whether the domain time is close to the current local time.
        Just calls the parent domain function and returns that. This is included here for completeness.
        """
        return self.domain.is_close_in_time_to_localhost(self.ldap_connection, allowed_drift_seconds)

    def find_certificate_authorities_for_domain(self, pem_format: bool=True):
        """ Attempt to discover the CAs within the domain and return info on their certificates.
        If a session was first established using an IP address or blind trust TLS, but we want to bootstrap our
        sessions to establish stronger trust, or write the CA certificates to a local truststore for other
        non-LDAP applications to use (e.g. establishing roots of trust for https or syslog over TLS), then it's
        helpful to grab the certificate authorities in the domain and their signing certificates.
        Not all domains run certificate authorities; some use public CAs or get certs from other PKI being run,
        so this isn't useful for everyone. But a lot of people do run CAs in their AD domains, and this is useful
        for them.

        :param pem_format: If True, return the certificates as strings in PEM format. Otherwise, return the
                           certificates as bytestrings in DER format. Defaults to True.
        :returns: A list of either PEM-formatted certificate strings or DER-formatted certificate byte strings,
                  representing the CA certificates of the CAs within the domain.
        """
        ca_filter = '({}={})'.format(ldap_constants.AD_ATTRIBUTE_OBJECT_CLASS,
                                     ldap_constants.CERTIFICATE_AUTHORITY_OBJECT_CLASS)
        search_loc = '{},{}'.format(ldap_constants.DOMAIN_WIDE_CONFIGURATIONS_CONTAINER,
                                    self.domain_search_base)
        res = self.ldap_connection.search(search_base=search_loc, search_filter=ca_filter, search_scope=SUBTREE,
                                          attributes=[ldap_constants.AD_ATTRIBUTE_CA_CERT])
        success, _, entities, _ = ldap_utils.process_ldap3_conn_return_value(self.ldap_connection, res)
        if not success:
            raise DomainSearchException('Failed to search domain for Certificate Authorities')
        entities = ldap_utils.remove_ad_search_refs(entities)
        logger.info('Found %s CAs within the domain', len(entities))
        ca_certs_der_fmt = []
        for entity in entities:
            # the bytes are returned in a 1-item list
            ca_cert_der_bytes = entity['attributes'][ldap_constants.AD_ATTRIBUTE_CA_CERT][0]
            ca_certs_der_fmt.append(ca_cert_der_bytes)

        if pem_format:
            return [ssl.DER_cert_to_PEM_cert(cert_bytes) for cert_bytes in ca_certs_der_fmt]
        return ca_certs_der_fmt

    def find_current_time_for_domain(self):
        """ Get the current time for the domain as a datetime object.
        Just calls the parent domain function and returns that. This is included here for completeness.
        :returns: A datetime object representing the current time in the domain.
        """
        return self.domain.find_current_time(self.ldap_connection)

    def find_dns_servers_for_domain(self):
        """ Attempt to discover the DNS servers within the domain and return info on them.
        If a session was first established using an IP address or blind trust TLS, but we want to bootstrap our
        sessions to use kerberos or TLS backed by CA certificates, we need proper DNS configured. For private
        domains (e.g. in a datacenter), we may run DNS servers within the domain. This function discovers
        computers with a "DNS/" service principal name, tries to look up IP addresses for them, and then
        returns that information.
        This won't always be useful, as DNS isn't always part of the AD domain, but it can help if we're bootstrapping
        a computer with manufacturer configurations to use the AD domain for everything based on a minimal starting
        configuration.

        :returns: A dictionary mapping DNS hostnames of DNS servers to IP addresses. The hostnames are provided in case
                  a caller is configuring DNS-over-TLS. If no IP address can be resolved for a hostname, it will map to
                  a None value.
                  https://datatracker.ietf.org/doc/html/rfc8310
        """
        dns_computer_filter = '(&({}={})({}={}))'.format(ldap_constants.AD_ATTRIBUTE_OBJECT_CLASS,
                                                         ldap_constants.COMPUTER_OBJECT_CLASS,
                                                         ldap_constants.AD_ATTRIBUTE_SERVICE_PRINCIPAL_NAMES,
                                                         ldap_constants.DNS_SERVICE_FILTER)
        # search the whole domain and grab the dns hostnames of the computers found
        res = self.ldap_connection.search(search_base=self.domain_search_base, search_filter=dns_computer_filter,
                                          search_scope=SUBTREE, attributes=[ldap_constants.AD_ATTRIBUTE_DNS_HOST_NAME])
        success, _, entities, _ = ldap_utils.process_ldap3_conn_return_value(self.ldap_connection, res)
        if not success:
            raise DomainSearchException('Failed to search domain for Computers hosting DNS services')
        entities = ldap_utils.remove_ad_search_refs(entities)
        logger.info('Found %s computers that host DNS services within the domain', len(entities))

        dns_results = {}
        for entity in entities:
            hostname = entity['attributes'][ldap_constants.AD_ATTRIBUTE_DNS_HOST_NAME]
            ip_addr = None
            try:
                ip_addr = socket.gethostbyname(hostname)
            except:
                logger.warning('Unable to resolve ip address for %s', hostname)

            if hostname in dns_results:
                logger.warning('Multiple computer entities exist in the domain serving DNS services with the DNS '
                               'hostname %s - this may indicate a domain misconfiguration issue.', hostname)
            dns_results[hostname] = ip_addr
        return dns_results

    def find_forest_schema_version(self):
        """ Attempt to determine the version of Windows Server set in the forest's schema.
        returns: An Enum of type ADVersion indicating the schema version.
        """
        search_loc = '{},{}'.format(ldap_constants.DOMAIN_CONTROLLER_SCHEMA_VERSION_SEARCH_CONTAINER,
                                    self.domain_search_base)
        res = self.ldap_connection.search(search_base=search_loc, search_filter=ldap_constants.FIND_ANYTHING_FILTER,
                                          search_scope=BASE, attributes=[ldap_constants.AD_ATTRIBUTE_GET_ALL_NON_VIRTUAL_ATTRS])
        success, _, entities, _ = ldap_utils.process_ldap3_conn_return_value(self.ldap_connection, res)
        if not success:
            raise DomainSearchException('Failed to search domain for schema.')
        entities = ldap_utils.remove_ad_search_refs(entities)
        if len(entities) == 0:
            raise DomainSearchException('The forest schema could not be found when searching the domain.')
        schema = entities[0]
        ad_schema_ver = schema['attributes'][ldap_constants.AD_SCHEMA_VERSION]
        return constants.ADVersion.get_version_from_schema_number(ad_schema_ver)

    def find_functional_level_for_domain(self):
        """ Attempt to discover the functional level of the domain and return it.
        This will indicate if the domain is operating at the level of a 2008, 2012R2, 2016, etc. domain.
        The functional level of a domain influences what functionality exists (e.g. 2003 cannot issue AES keys,
        2012 cannot use many TLS ciphers introduced with TLS1.3) and so it can be useful for determining what
        to do.
        :returns: An Enum of type ADFunctionalLevel indicating the functional level.
        """
        return self.domain.find_functional_level(self.ldap_connection)

    def find_supported_sasl_mechanisms_for_domain(self):
        """ Attempt to discover the SASL mechanisms supported by the domain and return them.
        This just builds upon the functionality that the domain has for this, as you don't need
        to be authenticated as anything other than anonymous to read this information (since it's
        often used to figure out how to authenticate).
        This is included in the session object for completeness.
        """
        return self.domain.find_supported_sasl_mechanisms(self.ldap_connection)

    def _find_user_or_group_and_attrs(self, search_base: str, search_filter:str, search_scope: str,
                                      attributes: List[str], size_limit: int, return_type):
        """ A helper function for common search and result parsing logic in other find functions for users
        and groups
        """
        attrs = self._figure_out_search_attributes_for_user_or_group(attributes)
        res = self.ldap_connection.search(search_base=search_base,
                                          search_filter=search_filter,
                                          search_scope=search_scope,
                                          size_limit=size_limit,
                                          attributes=attrs)
        _, _, resp, _ = ldap_utils.process_ldap3_conn_return_value(self.ldap_connection, res)
        resp = ldap_utils.remove_ad_search_refs(resp)
        if not resp:
            return []

        results = []
        for entry in resp:
            entry_attributes = entry['attributes']
            obj = return_type(entry['dn'], entry_attributes, self.domain)
            results.append(obj)
        return results

    def find_groups_by_common_name(self, group_name: str, attributes_to_lookup: List[str]=None):
        """ Find all groups with a given common name and return a list of ADGroup objects.
        This is particularly useful when you have multiple groups with the same name in different OUs
        as a result of a migration, and want to find them so you can combine them.

        :param group_name: The common name of the group(s) to be looked up.
        :param attributes_to_lookup: A list of additional LDAP attributes to query for the group. Regardless of
                                     what's specified, the groups' name and object class attributes will be queried.
        :returns: a list of ADGroup objects representing groups with the specified common name.
        """
        # build a compound filter for users with this common name
        search_filter = '(&({cn_attr}={cn}){type_filter})'.format(cn_attr=ldap_constants.AD_ATTRIBUTE_COMMON_NAME,
                                                                  cn=group_name,
                                                                  type_filter=ldap_constants.FIND_GROUP_FILTER)
        # a size limit of 0 means unlimited
        res = self._find_user_or_group_and_attrs(self.domain_search_base, search_filter, SUBTREE,
                                                 attributes_to_lookup, 0, ADGroup)
        logger.info('%s groups found with common name %s', len(res), group_name)
        return res

    def find_group_by_distinguished_name(self, group_dn: str, attributes_to_lookup: List[str]=None):
        """ Find a group in AD based on a specified distinguished name and return it along with any
        requested attributes.
        :param group_dn: The distinguished name of the group.
        :param attributes_to_lookup: A list of additional LDAP attributes to query for the group. Regardless of
                                     what's specified, the group's name and object class attributes will be queried.
        :returns: an ADGroup object or None if the group does not exist.
        """
        # since the distinguished name may be a relative distinguished name or complete one,
        # normalize it
        normalized_rdn = ldap_utils.normalize_object_location_in_domain(group_dn,
                                                                        self.domain_dns_name)
        search_dn = normalized_rdn + ',' + self.domain_search_base
        res = self._find_user_or_group_and_attrs(search_dn, ldap_constants.FIND_GROUP_FILTER, BASE,
                                                 attributes_to_lookup, 1, ADGroup)
        if not res:
            return None
        return res[0]

    def find_group_by_sam_name(self, group_name, attributes_to_lookup=None):
        """ Find a Group in AD based on a specified sAMAccountName name and return it along with any
        requested attributes.
        :param group_name: The sAMAccountName name of the group.
        :param attributes_to_lookup: A list of additional LDAP attributes to query for the group. Regardless of
                                     what's specified, the user's name and object class attributes will be queried.
        :returns: an ADGroup object or None if the user does not exist.
        """
        # build a compound filter for users with this samaccountname
        search_filter = '(&({sam_attr}={sam_name}){type_filter})'.format(sam_attr=ldap_constants.AD_ATTRIBUTE_SAMACCOUNT_NAME,
                                                                         sam_name=group_name,
                                                                         type_filter=ldap_constants.FIND_GROUP_FILTER)
        res = self._find_user_or_group_and_attrs(self.domain_search_base, search_filter, SUBTREE,
                                                 attributes_to_lookup, 1, ADGroup)
        if not res:
            return None
        return res[0]

    def find_users_by_common_name(self, user_name: str, attributes_to_lookup: List[str]=None):
        """ Find all users with a given common name and return a list of ADUser objects.
        This is particularly useful when you have multiple users with the same name in different OUs
        as a result of a migration, and want to find them so you can combine them.

        :param user_name: The common name of the user(s) to be looked up.
        :param attributes_to_lookup: A list of additional LDAP attributes to query for the users. Regardless of
                                     what's specified, the users' name and object class attributes will be queried.
        :returns: a list of ADUser objects representing users with the specified common name.
        """
        # build a compound filter for users with this common name
        search_filter = '(&({cn_attr}={cn}){type_filter})'.format(cn_attr=ldap_constants.AD_ATTRIBUTE_COMMON_NAME,
                                                                  cn=user_name,
                                                                  type_filter=ldap_constants.FIND_USER_FILTER)
        # a size limit of 0 means unlimited
        res = self._find_user_or_group_and_attrs(self.domain_search_base, search_filter, SUBTREE,
                                                 attributes_to_lookup, 0, ADUser)
        logger.info('%s users found with common name %s', len(res), user_name)
        return res

    def find_user_by_distinguished_name(self, user_dn: str, attributes_to_lookup: List[str]=None):
        """ Find a User in AD based on a specified distinguished name and return it along with any
        requested attributes.
        :param user_dn: The distinguished name of the user.
        :param attributes_to_lookup: A list of additional LDAP attributes to query for the user. Regardless of
                                     what's specified, the user's name and object class attributes will be queried.
        :returns: an ADUser object or None if the user does not exist.
        """
        # since the distinguished name may be a relative distinguished name or complete one,
        # normalize it
        normalized_rdn = ldap_utils.normalize_object_location_in_domain(user_dn,
                                                                        self.domain_dns_name)
        search_dn = normalized_rdn + ',' + self.domain_search_base
        res = self._find_user_or_group_and_attrs(search_dn, ldap_constants.FIND_USER_FILTER, BASE,
                                                 attributes_to_lookup, 1, ADUser)
        if not res:
            return None
        return res[0]

    def find_user_by_sam_name(self, user_name, attributes_to_lookup: List[str]=None):
        """ Find a User in AD based on a specified sAMAccountName name and return it along with any
        requested attributes.
        :param user_name: The sAMAccountName name of the user.
        :param attributes_to_lookup: A list of additional LDAP attributes to query for the user. Regardless of
                                     what's specified, the user's name and object class attributes will be queried.
        :returns: an ADUser object or None if the user does not exist.
        """
        # build a compound filter for users with this samaccountname
        search_filter = '(&({sam_attr}={sam_name}){type_filter})'.format(sam_attr=ldap_constants.AD_ATTRIBUTE_SAMACCOUNT_NAME,
                                                                         sam_name=user_name,
                                                                         type_filter=ldap_constants.FIND_USER_FILTER)
        res = self._find_user_or_group_and_attrs(self.domain_search_base, search_filter, SUBTREE,
                                                 attributes_to_lookup, 1, ADUser)
        if not res:
            return None
        return res[0]

    def _figure_out_search_attributes_for_user_or_group(self, attributes_to_lookup):
        """ There's some attributes we'll always get for users and groups, whether callers requested them or not.
        This combines those with any requested attributes
        """
        base_group_attrs = {ldap_constants.AD_ATTRIBUTE_SAMACCOUNT_NAME, ldap_constants.AD_ATTRIBUTE_OBJECT_CLASS,
                            ldap_constants.AD_ATTRIBUTE_COMMON_NAME}
        if attributes_to_lookup:
            base_group_attrs.update(set(base_group_attrs))
        # sort for reproducibility in eventual testing
        return sorted(list(base_group_attrs))
