import copy
import socket
import ssl

from ms_active_directory import logging_utils

from ldap3 import (
    BASE,
    Connection,
    SUBTREE,
)
from ldap3.protocol.rfc4511 import Control
from typing import List

import ms_active_directory.environment.constants as constants
import ms_active_directory.environment.ldap.ldap_format_utils as ldap_utils
import ms_active_directory.environment.ldap.ldap_constants as ldap_constants
import ms_active_directory.environment.security.security_config_utils as security_utils
import ms_active_directory.environment.security.security_config_constants as security_constants
import ms_active_directory.environment.security.security_descriptor_utils as sd_utils

from ms_active_directory.core.ad_computer import ADComputer
from ms_active_directory.core.ad_users_and_groups import ADGroup, ADUser, ADObject
from ms_active_directory.exceptions import (
    DomainSearchException,
    DuplicateNameException,
    InvalidLdapParameterException,
    MembershipModificationException,
    MembershipModificationRollbackException,
    ObjectCreationException,
    ObjectNotFoundException,
    PermissionDeniedException,
)

logger = logging_utils.get_logger()


class ADSession:

    def __init__(self, ldap_connection: Connection, domain, search_paging_size=100):
        self.ldap_connection = ldap_connection
        self.domain = domain
        self.domain_dns_name = self.domain.get_domain_dns_name()
        self.domain_search_base = ldap_utils.construct_ldap_base_dn_from_domain(self.domain_dns_name)
        # when checking whether we can create something within the domain, we check for sAMAccountName conflicts
        # and other conflicts depending on what's being created. when doing that validation we should always use
        # the plain domain base, whereas users might confine self.domain_search_base later to perform lookups
        # in a subsection of the domain
        self._domain_validation_search_base = self.domain_search_base
        # this is the size threshold at which we'll switch to paged searches. it's also the page size we'll use
        self.search_paging_size = search_paging_size

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

    def get_domain_search_base(self):
        """ Returns the LDAP search base used for all 'find' functions as the search base """
        return self.domain_search_base

    def set_domain_search_base(self, search_base: str):
        """ Set the search base to use for 'find' queries within the domain made by this session.
        This can be used to confine our search to a sub-container within the domain. This can improve
        the performance of lookups, avoid permissioning issues, and remove issues around duplicate
        records with the same common name.
        """
        # an empty string search base is a special search base and shouldn't be normalized
        if search_base != '':
            normalized_rdn = ldap_utils.normalize_object_location_in_domain(search_base,
                                                                            self.domain_dns_name)
            # always use the base 'DC=...,DC=...' for our normalization
            search_base = normalized_rdn + ',' + self._domain_validation_search_base
        self.domain_search_base = search_base

    def get_search_paging_size(self):
        return self.search_paging_size

    def set_search_paging_size(self, new_size: int):
        self.search_paging_size = new_size

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

    # FUNCTIONS FOR FINDING DOMAIN INFORMATION

    def is_domain_close_in_time_to_localhost(self, allowed_drift_seconds=None):
        """ Get whether the domain time is close to the current local time.
        Just calls the parent domain function and returns that. This is included here for completeness.
        """
        return self.domain.is_close_in_time_to_localhost(self.ldap_connection, allowed_drift_seconds)

    def find_certificate_authorities_for_domain(self, pem_format: bool=True, controls: List[Control]=None):
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
        :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                         whether or not certain properties/attributes are critical, which influences whether a search
                         may succeed or fail based on their availability.
        :returns: A list of either PEM-formatted certificate strings or DER-formatted certificate byte strings,
                  representing the CA certificates of the CAs within the domain.
        """
        ca_filter = '({}={})'.format(ldap_constants.AD_ATTRIBUTE_OBJECT_CLASS,
                                     ldap_constants.CERTIFICATE_AUTHORITY_OBJECT_CLASS)
        search_loc = '{},{}'.format(ldap_constants.DOMAIN_WIDE_CONFIGURATIONS_CONTAINER,
                                    self.domain_search_base)
        res = self.ldap_connection.search(search_base=search_loc, search_filter=ca_filter, search_scope=SUBTREE,
                                          attributes=[ldap_constants.AD_ATTRIBUTE_CA_CERT],
                                          controls=controls)
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

    def find_dns_servers_for_domain(self, controls: List[Control]=None):
        """ Attempt to discover the DNS servers within the domain and return info on them.
        If a session was first established using an IP address or blind trust TLS, but we want to bootstrap our
        sessions to use kerberos or TLS backed by CA certificates, we need proper DNS configured. For private
        domains (e.g. in a datacenter), we may run DNS servers within the domain. This function discovers
        computers with a "DNS/" service principal name, tries to look up IP addresses for them, and then
        returns that information.
        This won't always be useful, as DNS isn't always part of the AD domain, but it can help if we're bootstrapping
        a computer with manufacturer configurations to use the AD domain for everything based on a minimal starting
        configuration.

        :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                         whether or not certain properties/attributes are critical, which influences whether a search
                         may succeed or fail based on their availability.
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
                                          search_scope=SUBTREE, attributes=[ldap_constants.AD_ATTRIBUTE_DNS_HOST_NAME],
                                          controls=controls)
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
                                          search_scope=BASE, attributes=[ldap_constants.AD_ATTRIBUTE_GET_ALL_NON_VIRTUAL_ATTRS],
                                          size_limit=1)
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

    # FUNCTIONS FOR FINDING USERS AND GROUPS

    def _find_ad_objects_and_attrs(self, search_base: str, search_filter:str, search_scope: str,
                                   attributes: List[str], size_limit: int, return_type, controls: List[Control]):
        """ A helper function for common search and result parsing logic in other find functions for users
        and groups
        """
        attrs = self._figure_out_search_attributes_for_user_or_group(attributes)
        # do a paged search for big searches so that if we're in a multi-threaded application, we're more interruptable
        paginate = size_limit == 0 or size_limit > self.search_paging_size
        if paginate:
            res = self.ldap_connection.extend.standard.paged_search(search_base=search_base,
                                                                    search_filter=search_filter,
                                                                    search_scope=search_scope,
                                                                    size_limit=size_limit,
                                                                    attributes=attrs,
                                                                    controls=controls,
                                                                    paged_size=self.search_paging_size,
                                                                    generator=False)
        else:
            # for small searches or those taking up less than 1 page, just do a normal search since it's
            # lighter weight
            res = self.ldap_connection.search(search_base=search_base,
                                              search_filter=search_filter,
                                              search_scope=search_scope,
                                              size_limit=size_limit,
                                              attributes=attrs,
                                              controls=controls)
        _, _, resp, _ = ldap_utils.process_ldap3_conn_return_value(self.ldap_connection, res,
                                                                   paginated_response=paginate)
        resp = ldap_utils.remove_ad_search_refs(resp)
        if not resp:
            return []

        results = []
        for entry in resp:
            entry_attributes = entry['attributes']
            obj = return_type(entry['dn'], entry_attributes, self.domain)
            results.append(obj)
        return results

    def find_objects_with_attribute(self, attribute_name: str, attribute_value, attributes_to_lookup: List[str]=None,
                                    size_limit: int=0, object_class: str=None, return_type=None, controls: List[Control]=None):
        """ Find all AD objects that possess the specified attribute with the specified value and return them.

        :param attribute_name: The LDAP name of the attribute to be used in the search.
        :param attribute_value: The value that returned objects should possess for the attribute.
        :param attributes_to_lookup: A list of additional LDAP attributes to query for the group. Regardless of
                                     what's specified, the groups' name and object class attributes will be queried.
        :param size_limit: An integer indicating a limit to place the number of results the search will return.
                           If not specified, defaults to 0, meaning unlimited.
        :param object_class: Optional. The object class to filter on when searching. Defaults to 'top' which will
                             include all objects in AD.
        :param return_type: Optional. The class to use to represent the returned objects. Defaults to ADObject.
                            If a generic search is being done, or an object class is used that is not yet supported
                            by this library, using ADObject is recommended.
        :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                         whether or not certain properties/attributes are critical, which influences whether a search
                         may succeed or fail based on their availability.
        :returns: a list of ADObject objects representing groups with the specified value for the specified attribute.
        """
        if return_type is None:
            return_type = ADObject
        if object_class is None:
            # top is the top level object class that all objects possess. it's as generic as you can get
            object_class = ldap_constants.TOP_OBJECT_CLASS

        # if our attribute value looks like a DN, escape it like one. otherwise, escape normally
        if isinstance(attribute_value, bytes):
            escaped_val = ldap_utils.escape_bytestring_for_filter(attribute_value)
        elif ldap_utils.is_dn(attribute_value):
            escaped_val = ldap_utils.escape_dn_for_filter(attribute_value)
        else:
            escaped_val = ldap_utils.escape_generic_filter_value(attribute_value)
        search_filter = ('(&({obj_class_attr}={obj_class})({attr}={attr_val}))'
                         .format(obj_class_attr=ldap_constants.AD_ATTRIBUTE_OBJECT_CLASS,
                                 obj_class=object_class, attr=attribute_name,
                                 attr_val=escaped_val))
        # at a minimum, always look up the thing we're filtering on
        if attributes_to_lookup is None:
            attributes_to_lookup = [attribute_name]
        if attribute_name not in attributes_to_lookup:
            attributes_to_lookup.append(attribute_name)
        # a size limit of 0 means unlimited
        res = self._find_ad_objects_and_attrs(self.domain_search_base, search_filter, SUBTREE,
                                              attributes_to_lookup, size_limit, return_type, controls)
        logger.info('%s %s objects found with %s value %s', len(res), object_class, attribute_name, attribute_value)
        return res

    def find_groups_by_attribute(self, attribute_name: str, attribute_value, attributes_to_lookup: List[str]=None,
                                 size_limit: int=0, controls: List[Control]=None):
        """ Find all groups that possess the specified attribute with the specified value, and return a list of ADGroup
        objects.

        :param attribute_name: The LDAP name of the attribute to be used in the search.
        :param attribute_value: The value that returned groups should possess for the attribute.
        :param attributes_to_lookup: A list of additional LDAP attributes to query for the group. Regardless of
                                     what's specified, the groups' name and object class attributes will be queried.
        :param size_limit: An integer indicating a limit to place the number of results the search will return.
                           If not specified, defaults to 0, meaning unlimited.
        :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                         whether or not certain properties/attributes are critical, which influences whether a search
                         may succeed or fail based on their availability.
        :returns: a list of ADGroup objects representing groups with the specified value for the specified attribute.
        """
        return self.find_objects_with_attribute(attribute_name, attribute_value, attributes_to_lookup, size_limit,
                                                ldap_constants.GROUP_OBJECT_CLASS, ADGroup, controls)

    def find_groups_by_common_name(self, group_name: str, attributes_to_lookup: List[str]=None,
                                   controls: List[Control]=None):
        """ Find all groups with a given common name and return a list of ADGroup objects.
        This is particularly useful when you have multiple groups with the same name in different OUs
        as a result of a migration, and want to find them so you can combine them.

        :param group_name: The common name of the group(s) to be looked up.
        :param attributes_to_lookup: A list of additional LDAP attributes to query for the group. Regardless of
                                     what's specified, the groups' name and object class attributes will be queried.
        :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                         whether or not certain properties/attributes are critical, which influences whether a search
                         may succeed or fail based on their availability.
        :returns: a list of ADGroup objects representing groups with the specified common name.
        """
        # build a compound filter for users with this common name
        search_filter = '(&({cn_attr}={cn}){type_filter})'.format(cn_attr=ldap_constants.AD_ATTRIBUTE_COMMON_NAME,
                                                                  cn=group_name,
                                                                  type_filter=ldap_constants.FIND_GROUP_FILTER)
        # a size limit of 0 means unlimited
        res = self._find_ad_objects_and_attrs(self.domain_search_base, search_filter, SUBTREE,
                                              attributes_to_lookup, 0, ADGroup, controls)
        logger.info('%s groups found with common name %s', len(res), group_name)
        return res

    def find_group_by_distinguished_name(self, group_dn: str, attributes_to_lookup: List[str]=None,
                                         controls: List[Control]=None):
        """ Find a group in AD based on a specified distinguished name and return it along with any
        requested attributes.
        :param group_dn: The distinguished name of the group.
        :param attributes_to_lookup: A list of additional LDAP attributes to query for the group. Regardless of
                                     what's specified, the group's name and object class attributes will be queried.
        :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                         whether or not certain properties/attributes are critical, which influences whether a search
                         may succeed or fail based on their availability.
        :returns: an ADGroup object or None if the group does not exist.
        """
        # since the distinguished name may be a relative distinguished name or complete one,
        # normalize it
        normalized_rdn = ldap_utils.normalize_object_location_in_domain(group_dn,
                                                                        self.domain_dns_name)
        search_dn = normalized_rdn + ',' + self.domain_search_base
        res = self._find_ad_objects_and_attrs(search_dn, ldap_constants.FIND_GROUP_FILTER, BASE,
                                              attributes_to_lookup, 1, ADGroup, controls)
        if not res:
            return None
        return res[0]

    def find_group_by_sam_name(self, group_name: str, attributes_to_lookup: List[str]=None,
                               controls: List[Control]=None):
        """ Find a Group in AD based on a specified sAMAccountName name and return it along with any
        requested attributes.
        :param group_name: The sAMAccountName name of the group.
        :param attributes_to_lookup: A list of additional LDAP attributes to query for the group. Regardless of
                                     what's specified, the group's name and object class attributes will be queried.
        :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                         whether or not certain properties/attributes are critical, which influences whether a search
                         may succeed or fail based on their availability.
        :returns: an ADGroup object or None if the group does not exist.
        """
        # build a compound filter for users with this samaccountname
        search_filter = '(&({sam_attr}={sam_name}){type_filter})'.format(sam_attr=ldap_constants.AD_ATTRIBUTE_SAMACCOUNT_NAME,
                                                                         sam_name=group_name,
                                                                         type_filter=ldap_constants.FIND_GROUP_FILTER)
        res = self._find_ad_objects_and_attrs(self.domain_search_base, search_filter, SUBTREE,
                                              attributes_to_lookup, 1, ADGroup, controls)
        if not res:
            return None
        return res[0]

    def find_group_by_sid(self, group_sid, attributes_to_lookup: List[str]=None, controls: List[Control]=None):
        """ Find a Group in AD given its SID.
        This function takes in a group's objectSID and then looks up the group in AD using it. SIDs are unique
        so only a single entry can be found at most.
        The group SID can be in many formats (well known SID enum, ObjectSID object, canonical SID format,
        or bytes) and so all 4 possible formats are handled.
        :param group_sid: The group SID. This may either be a well-known SID enum, an ObjectSID object, a string SID
                          in canonical format (e.g. S-1-1-0), object SID bytes, or the hex representation of such bytes.
        :param attributes_to_lookup: A list of additional LDAP attributes to query for the group. Regardless of
                                     what's specified, the group's name and object class attributes will be queried.
        :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                         whether or not certain properties/attributes are critical, which influences whether a search
                         may succeed or fail based on their availability.
        :returns: an ADGroup object or None if the group does not exist.
        """
        return self.find_object_by_sid(group_sid, attributes_to_lookup, object_class=ldap_constants.GROUP_OBJECT_CLASS,
                                       return_type=ADGroup, controls=controls)

    def find_group_by_name(self, group_name: str, attributes_to_lookup: List[str]=None, controls: List[Control]=None):
        """ Find a Group in AD based on a provided name.
        This function takes in a generic name which can be either a distinguished name, a common name, or a
        sAMAccountName, and tries to find a unique group identified by it and return information on the group.
        :param group_name: The name of the group, which may be a DN, common name, or sAMAccountName.
        :param attributes_to_lookup: A list of additional LDAP attributes to query for the group. Regardless of
                                     what's specified, the group's name and object class attributes will be queried.
        :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                         whether or not certain properties/attributes are critical, which influences whether a search
                         may succeed or fail based on their availability.
        :returns: an ADGroup object or None if the group does not exist.
        :raises: a DuplicateNameException if more than one entry exists with this name.
        """
        return self._find_by_name_common(group_name, attributes_to_lookup, is_user=False, controls=controls)

    def find_object_by_sid(self, sid, attributes_to_lookup: List[str]=None, object_class: str=None,
                           return_type=None, controls: List[Control]=None):
        """ Find any object in AD given its SID.
        This function takes in a user's objectSID and then looks up the user in AD using it. SIDs are unique
        so only a single entry can be found at most.
        The user SID can be in many formats (well known SID enum, ObjectSID object, canonical SID format,
        or bytes) and so all 4 possible formats are handled.
        :param sid: The object's SID. This may either be a well-known SID enum, an ObjectSID object, a string SID
                    in canonical format (e.g. S-1-1-0), object SID bytes, or the hex representation of such bytes.
        :param attributes_to_lookup: A list of additional LDAP attributes to query for the object. Regardless of
                                     what's specified, the object's name and object class attributes will be queried.
        :param object_class: Optional. The object class to filter on when searching. Defaults to 'top' which will
                             include all objects in AD.
        :param return_type: Optional. The class to use to represent the returned objects. Defaults to ADObject.
                            If a generic search is being done, or an object class is used that is not yet supported
                            by this library, using ADObject is recommended.
        :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                         whether or not certain properties/attributes are critical, which influences whether a search
                         may succeed or fail based on their availability.
        :returns: an ADObject object or None if the group does not exist.
        """
        # if it's a string, or a well known SID, convert it to an ObjectSid object
        sid_obj_or_bytes = sid
        if isinstance(sid, str) and sid.upper().startswith('S-'):
            logger.debug('Converting string SID to ObjectSID object')
            sd = sd_utils.ObjectSid()
            sd.from_canonical_string_format(sid.upper())
            sid_obj_or_bytes = sd
        elif isinstance(sid, security_constants.WellKnownSID):
            logger.debug('Converting Well Known SID to ObjectSID object')
            sd = sd_utils.ObjectSid()
            sd.from_canonical_string_format(sid.value)
            sid_obj_or_bytes = sd

        # we must either have an ObjectSid or bytes at this point. we want to end up with bytes
        sid_bytes = sid_obj_or_bytes
        if isinstance(sid_obj_or_bytes, sd_utils.ObjectSid):
            sid_bytes = sid_obj_or_bytes.get_data()
        elif not isinstance(sid_obj_or_bytes, bytes):
            raise InvalidLdapParameterException('Object SIDs, regardless of object class, must be specified as one of '
                                                'the following types: WellKnownSID enum, ObjectSid object, String in '
                                                'canonical format beginning with S-, bytes.')

        results = self.find_objects_with_attribute(ldap_constants.AD_ATTRIBUTE_OBJECT_SID, sid_bytes,
                                                   attributes_to_lookup, 1, object_class, return_type, controls)
        if results:
            return results[0]
        return None

    def find_users_by_attribute(self, attribute_name: str, attribute_value, attributes_to_lookup: List[str]=None,
                                size_limit: int=0, controls: List[Control]=None):
        """ Find all users that possess the specified attribute with the specified value, and return a list of ADUser
        objects.

        :param attribute_name: The LDAP name of the attribute to be used in the search.
        :param attribute_value: The value that returned groups should possess for the attribute.
        :param attributes_to_lookup: A list of additional LDAP attributes to query for the users. Regardless of
                                     what's specified, the users' name and object class attributes will be queried.
        :param size_limit: An integer indicating a limit to place the number of results the search will return.
                           If not specified, defaults to 0, meaning unlimited.
        :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                         whether or not certain properties/attributes are critical, which influences whether a search
                         may succeed or fail based on their availability.
        :returns: a list of ADUser objects representing groups with the specified value for the specified attribute.
        """
        return self.find_objects_with_attribute(attribute_name, attribute_value, attributes_to_lookup, size_limit,
                                                ldap_constants.USER_OBJECT_CLASS, ADUser, controls)

    def find_users_by_common_name(self, user_name: str, attributes_to_lookup: List[str]=None,
                                  controls: List[Control]=None):
        """ Find all users with a given common name and return a list of ADUser objects.
        This is particularly useful when you have multiple users with the same name in different OUs
        as a result of a migration, and want to find them so you can combine them.

        :param user_name: The common name of the user(s) to be looked up.
        :param attributes_to_lookup: A list of additional LDAP attributes to query for the users. Regardless of
                                     what's specified, the users' name and object class attributes will be queried.
        :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                         whether or not certain properties/attributes are critical, which influences whether a search
                         may succeed or fail based on their availability.
        :returns: a list of ADUser objects representing users with the specified common name.
        """
        # build a compound filter for users with this common name
        search_filter = '(&({cn_attr}={cn}){type_filter})'.format(cn_attr=ldap_constants.AD_ATTRIBUTE_COMMON_NAME,
                                                                  cn=user_name,
                                                                  type_filter=ldap_constants.FIND_USER_FILTER)
        # a size limit of 0 means unlimited
        res = self._find_ad_objects_and_attrs(self.domain_search_base, search_filter, SUBTREE,
                                              attributes_to_lookup, 0, ADUser, controls)
        logger.info('%s users found with common name %s', len(res), user_name)
        return res

    def find_user_by_distinguished_name(self, user_dn: str, attributes_to_lookup: List[str]=None,
                                        controls: List[Control]=None):
        """ Find a User in AD based on a specified distinguished name and return it along with any
        requested attributes.
        :param user_dn: The distinguished name of the user.
        :param attributes_to_lookup: A list of additional LDAP attributes to query for the user. Regardless of
                                     what's specified, the user's name and object class attributes will be queried.
        :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                         whether or not certain properties/attributes are critical, which influences whether a search
                         may succeed or fail based on their availability.
        :returns: an ADUser object or None if the user does not exist.
        """
        # since the distinguished name may be a relative distinguished name or complete one,
        # normalize it
        normalized_rdn = ldap_utils.normalize_object_location_in_domain(user_dn,
                                                                        self.domain_dns_name)
        search_dn = normalized_rdn + ',' + self.domain_search_base
        res = self._find_ad_objects_and_attrs(search_dn, ldap_constants.FIND_USER_FILTER, BASE,
                                              attributes_to_lookup, 1, ADUser, controls)
        if not res:
            return None
        return res[0]

    def find_user_by_sam_name(self, user_name, attributes_to_lookup: List[str]=None, controls: List[Control]=None):
        """ Find a User in AD based on a specified sAMAccountName name and return it along with any
        requested attributes.
        :param user_name: The sAMAccountName name of the user.
        :param attributes_to_lookup: A list of additional LDAP attributes to query for the user. Regardless of
                                     what's specified, the user's name and object class attributes will be queried.
        :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                         whether or not certain properties/attributes are critical, which influences whether a search
                         may succeed or fail based on their availability.
        :returns: an ADUser object or None if the user does not exist.
        """
        # build a compound filter for users with this samaccountname
        search_filter = '(&({sam_attr}={sam_name}){type_filter})'.format(sam_attr=ldap_constants.AD_ATTRIBUTE_SAMACCOUNT_NAME,
                                                                         sam_name=user_name,
                                                                         type_filter=ldap_constants.FIND_USER_FILTER)
        res = self._find_ad_objects_and_attrs(self.domain_search_base, search_filter, SUBTREE,
                                              attributes_to_lookup, 1, ADUser, controls)
        if not res:
            return None
        return res[0]

    def find_user_by_sid(self, user_sid, attributes_to_lookup: List[str]=None, controls: List[Control]=None):
        """ Find a User in AD given its SID.
        This function takes in a user's objectSID and then looks up the user in AD using it. SIDs are unique
        so only a single entry can be found at most.
        The user SID can be in many formats (well known SID enum, ObjectSID object, canonical SID format,
        or bytes) and so all 4 possible formats are handled.
        :param user_sid: The user SID. This may either be a well-known SID enum, an ObjectSID object, a string SID
                         in canonical format (e.g. S-1-1-0), object SID bytes, or the hex representation of such bytes.
        :param attributes_to_lookup: A list of additional LDAP attributes to query for the user. Regardless of
                                     what's specified, the user's name and object class attributes will be queried.
        :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                         whether or not certain properties/attributes are critical, which influences whether a search
                         may succeed or fail based on their availability.
        :returns: an ADUser object or None if the group does not exist.
        """
        return self.find_object_by_sid(user_sid, attributes_to_lookup, object_class=ldap_constants.USER_OBJECT_CLASS,
                                       return_type=ADUser, controls=controls)

    def find_user_by_name(self, user_name: str, attributes_to_lookup: List[str]=None,
                          controls: List[Control]=None):
        """ Find a User in AD based on a provided name.
        This function takes in a generic name which can be either a distinguished name, a common name, or a
        sAMAccountName, and tries to find a unique user identified by it and return information on the user.
        :param user_name: The name of the user, which may be a DN, common name, or sAMAccountName.
        :param attributes_to_lookup: A list of additional LDAP attributes to query for the user. Regardless of
                                     what's specified, the user's name and object class attributes will be queried.
        :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                         whether or not certain properties/attributes are critical, which influences whether a search
                         may succeed or fail based on their availability.
        :returns: an ADUser object or None if the user does not exist.
        :raises: a DuplicateNameException if more than one entry exists with this name.
        """
        return self._find_by_name_common(user_name, attributes_to_lookup, is_user=True, controls=controls)

    def _find_by_name_common(self, name: str, attributes_to_lookup: List[str], is_user: bool=True,
                             controls: List[Control]=None):
        """ A helper function to find things by a unique name.
        Depending on the type of object, it first checks if the name is a DN. We then perform
        the appropriate lookup by DN if it is. Otherwise, we first try a lookup by sAMAccountName;
        if that works we return that. If it doesn't, we try a lookup by common name. If that finds
        1 result, we return it. Otherwise, we raise a duplicate name error.
        """
        is_dn = ldap_utils.is_dn(name)
        dn_lookup_func = self.find_group_by_distinguished_name
        sam_lookup_func = self.find_group_by_sam_name
        cn_lookup_func = self.find_groups_by_common_name
        if is_user:
            dn_lookup_func = self.find_user_by_distinguished_name
            sam_lookup_func = self.find_user_by_sam_name
            cn_lookup_func = self.find_users_by_common_name

        if is_dn:
            return dn_lookup_func(name, attributes_to_lookup, controls=controls)
        res = sam_lookup_func(name, attributes_to_lookup)
        if res:
            return res
        result_list = cn_lookup_func(name, attributes_to_lookup, controls=controls)
        if not result_list:
            return None
        if len(result_list) > 1:
            insert = 'user' if is_user else 'group'
            raise DuplicateNameException('Multiple {}s found with name "{}". Please either repeat the search '
                                         'using a distinguished name or sAMAccountName, or adjust the session '
                                         'search base using set_domain_search_base to limit searches such that only '
                                         'one result is found. Alternatively you may perform a lookup by common name '
                                         'and select which {} entry you want to use from multiple.'
                                         .format(insert, name, insert))
        return result_list[0]

    def _figure_out_search_attributes_for_user_or_group(self, attributes_to_lookup):
        """ There's some attributes we'll always get for users and groups, whether callers requested them or not.
        This combines those with any requested attributes
        """
        base_attrs = {ldap_constants.AD_ATTRIBUTE_SAMACCOUNT_NAME, ldap_constants.AD_ATTRIBUTE_OBJECT_CLASS,
                      ldap_constants.AD_ATTRIBUTE_COMMON_NAME}
        if attributes_to_lookup:
            base_attrs.update(set(attributes_to_lookup))
        # sort for reproducibility in eventual testing
        return sorted(list(base_attrs))

    # FUNCTIONS FOR FINDING MEMBERSHIP INFORMATION

    def find_groups_for_entities(self, entities: List, attributes_to_lookup: List[str]=None,
                                 lookup_by_name_fn: callable=None, controls: List[Control]=None):
        """ Find the parent groups for all of the entities in a List.
        These entities may be users, groups, or anything really because Active Directory uses the "groupOfNames" style
        membership tracking, so all group members are just represented as distinguished names regardless of type.
        If the elements of entities are strings and are not distinguished names, then lookup_by_name_fn will be used
        to look up the appropriate ADObject for the entity and get its distinguished name.

        The parent groups of all the entities will then be queried, and the attributes specified will be looked up
        (if any). A dictionary mapping the original entities to lists of ADGroup objects will be returned.

        :param entities: A list of either ADObject objects or strings. These represent the objects whose parent groups
                         are being queried.
        :param attributes_to_lookup: A list of LDAP attributes to query about the parent groups, in addition to the
                                     default ones queries. Optional.
        :param lookup_by_name_fn: An optional function to call to map entities to ADObjects when the members of entities
                                  are strings that are not LDAP distinguished names.
        :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                         whether or not certain properties/attributes are critical, which influences whether a search
                         may succeed or fail based on their availability.
        :returns: A dictionary mapping input entities to lists of ADGroup object representing their parent groups.
        :raises: a DuplicateNameException if an entity name is specified and more than one entry exists with the name.
        :raises: InvalidLdapParameterException if any non-string non-ADObject types are found in entities, or if any
                 non-distinguished name strings are specified.
        """
        # make a map of entity distinguished names to entities passed in. we'll use this when constructing
        # our return dictionary as well
        entity_dns = ldap_utils.normalize_entities_to_entity_dns(entities, lookup_by_name_fn, controls)

        filter_pieces = []
        for entity_dn in entity_dns:
            filter_piece = '({}={})'.format(ldap_constants.AD_ATTRIBUTE_MEMBER,
                                            ldap_utils.escape_dn_for_filter(entity_dn))
            filter_pieces.append(filter_piece)
        all_member_filters = ''.join(filter_pieces)
        # this filter can get really really big, because DNs are long and we can have a lot of entities.
        # AD does have a limit on request size; that limit is huge by default though - 10MB - and can be raised
        # https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2003/cc755809(v=ws.10)
        chain_filter = ('(&({obj_cls_attr}={obj_cls})(|{member_filters}))'
                        .format(obj_cls_attr=ldap_constants.AD_ATTRIBUTE_OBJECT_CLASS,
                                obj_cls=ldap_constants.GROUP_OBJECT_CLASS,
                                member_filters=all_member_filters))
        filter_length = len(chain_filter)
        logger.info('Querying parent groups of %s entitites using a filter of length %s',
                    len(entities), filter_length)
        # if our filter is more than 95% of the default limit, log at a warning level to make debugging issues easier
        if filter_length > 10000000:
            logger.warning('Filter length exceeds 95% of the DEFAULT active directory limit on request size, so this '
                           'request may be rejected, in which case you should re-attempt with fewer entities in '
                           'batches', filter_length)

        # make sure member is included in our results
        if attributes_to_lookup is None or attributes_to_lookup is []:
            attributes_to_lookup = []
        if ldap_constants.AD_ATTRIBUTE_MEMBER not in attributes_to_lookup:
            attributes_to_lookup.append(ldap_constants.AD_ATTRIBUTE_MEMBER)
        # look up our results
        results = self._find_ad_objects_and_attrs(self.domain_search_base, chain_filter, SUBTREE,
                                                  attributes_to_lookup, 0, ADGroup, controls)
        logger.info('Found %s unique parent groups across all %s entities', len(results), len(entities))
        mapping_dict = {}
        for entity in entities:
            mapping_dict[entity] = []

        # go over our results and for each one, figure out which input entities have the group as a parent
        # (multiple entities could share parents)
        for result in results:
            # groups can have a lot of members. converting the member list to a set keeps
            # the checking of all input entities to O(n) instead of O(n^2) and keeps the total
            # complexity of checking all input entities for all results to O(n^2) instead of O(n^3).
            # cast all members to lowercase for a case-insensitive membership check. our normalization
            # function gave use lowercase DNs
            member_set = set(member.lower() for member in result.get(ldap_constants.AD_ATTRIBUTE_MEMBER))
            for entity_dn in entity_dns:
                if entity_dn in member_set:
                    # get our input entity for the result dict
                    entity = entity_dns[entity_dn]
                    mapping_dict[entity].append(result)
        return mapping_dict

    def find_groups_for_group(self, group, attributes_to_lookup: List[str]=None, controls: List[Control]=None):
        """ Find the groups that a group belongs to, look up attributes of theirs, and return information about them.

        :param group: The group to lookup group memberships for. This can either be an ADGroup or a string name of an
                      AD group. If it is a string, the group will be looked up first to get unique distinguished name
                      information about it unless it is a distinguished name.
        :param attributes_to_lookup: A list of string LDAP attributes to look up in addition to our basic attributes.
        :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                         whether or not certain properties/attributes are critical, which influences whether a search
                         may succeed or fail based on their availability.
        :returns: A list of ADGroup objects representing the groups that this group belongs to.
        :raises: a DuplicateNameException if a group name is specified and more than one entry exists with the name.
        :raises: a InvalidLdapParameterException if the group name is not a string or ADGroup.
        """
        result_dict = self.find_groups_for_entities([group], attributes_to_lookup, self.find_group_by_name,
                                                    controls)
        return result_dict[group]

    def find_groups_for_groups(self, groups: List, attributes_to_lookup: List[str]=None, controls: List[Control]=None):
        """ Find the groups that a list of groups belong to, look up attributes of theirs, and return information about
        them.

        :param groups: The groups to lookup group memberships for. This can be a list of either ADGroup objects or
                       string names of AD groups. If they are strings, the groups will be looked up first to get unique
                       distinguished name information about them unless they are distinguished names.
        :param attributes_to_lookup: A list of string LDAP attributes to look up in addition to our basic attributes.
        :returns: A dictionary mapping groups to lists of ADGroup objects representing the groups that they belong to.
        :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                         whether or not certain properties/attributes are critical, which influences whether a search
                         may succeed or fail based on their availability.
        :raises: a DuplicateNameException if a group name is specified and more than one entry exists with the name.
        :raises: a InvalidLdapParameterException if any groups are not a string or ADGroup.
        """
        return self.find_groups_for_entities(groups, attributes_to_lookup, self.find_group_by_name, controls)

    def find_groups_for_user(self, user, attributes_to_lookup: List[str]=None, controls: List[Control]=None):
        """ Find the groups that a user belongs to, look up attributes of theirs, and return information about them.

        :param user: The user to lookup group memberships for. This can either be an ADUser or a string name of an
                     AD user. If it is a string, the user will be looked up first to get unique distinguished name
                     information about it unless it is a distinguished name.
        :param attributes_to_lookup: A list of string LDAP attributes to look up in addition to our basic attributes.
        :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                         whether or not certain properties/attributes are critical, which influences whether a search
                         may succeed or fail based on their availability.
        :returns: A list of ADGroup objects representing the groups that this user belongs to.
        :raises: a DuplicateNameException if a user name is specified and more than one entry exists with the name.
        :raises: a InvalidLdapParameterException if the yser name is not a string or ADUser.
        """
        result_dict = self.find_groups_for_entities([user], attributes_to_lookup, self.find_user_by_name, controls)
        return result_dict[user]

    def find_groups_for_users(self, users: List, attributes_to_lookup: List[str]=None, controls: List[Control]=None):
        """ Find the groups that a list of users belong to, look up attributes of theirs, and return information about
        them.

        :param users: The users to lookup group memberships for. This can be a list of either ADUser objects or
                      string names of AD users. If they are strings, the users will be looked up first to get unique
                      distinguished name information about them unless they are distinguished names.
        :param attributes_to_lookup: A list of string LDAP attributes to look up in addition to our basic attributes.
        :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                         whether or not certain properties/attributes are critical, which influences whether a search
                         may succeed or fail based on their availability.
        :returns: A dictionary mapping users to lists of ADGroup objects representing the groups that they belong to.
        :raises: a DuplicateNameException if a user name is specified and more than one entry exists with the name.
        :raises: a InvalidLdapParameterException if any users are not a string or ADUser.
        """
        return self.find_groups_for_entities(users, attributes_to_lookup, self.find_user_by_name, controls)

    # FUNCTIONS FOR MODIFYING MEMBERSHIPS

    def _something_members_to_or_from_groups(self, members: List, groups_to_modify: List,
                                             member_lookup_fn: callable, stop_and_rollback_on_error: bool,
                                             adding: bool, controls: List[Control]):
        """ Either add or remove members to/from groups. Members may be users or groups or string distinguished names.
        If there are any failures adding/removing for a group, and stop_and_rollback_on_error is True, we will attempt
        to undo the changes that have been done. If rollback fails, we will raise an exception. If it succeeds, we still
        raise an exception, but of a different type.

        If stop_and_rollback_on_error is False, we ignore failures and keep going.
        We return a list of successfully modified groups at the end.
        """
        # figure out which function to use
        member_modify_fn = self.ldap_connection.extend.microsoft.remove_members_from_groups
        verb = 'remove'
        if adding:
            member_modify_fn = self.ldap_connection.extend.microsoft.add_members_to_groups
            verb = 'add'

        # normalize our inputs to get lists of lowercase dns
        normalized_member_dns = ldap_utils.normalize_entities_to_entity_dns(members,
                                                                            member_lookup_fn,
                                                                            controls)
        member_dn_list = list(normalized_member_dns.keys())
        normalized_target_group_dns = ldap_utils.normalize_entities_to_entity_dns(groups_to_modify,
                                                                                  self.find_group_by_name,
                                                                                  controls)
        target_group_list = list(normalized_target_group_dns.keys())

        # track successful groups in case we need to rollback, and rollback status
        successful_groups = []
        failing_group = None
        for group_dn in target_group_list:
            logger.info('Attempting to %s the following members to/from group %s : %s', verb, member_dn_list,
                        group_dn)
            # by setting fix to True, we ignore members already in the group and make this idempotent
            res = member_modify_fn(member_dn_list, [group_dn], fix=True)
            # the function returns a boolean on whether it succeeded or not
            if not res:
                failing_group = group_dn
                logger.error('Failure occurred attempting to %s members to/from group %s', verb, group_dn)
                if stop_and_rollback_on_error:
                    if not successful_groups:
                        logger.info('No successful groups to rollback')
                        break
                    logger.warning('Rolling back member %s operations to groups %s', verb, successful_groups)
                    # reverse the operation
                    new_op = not adding
                    try:
                        # don't attempt to rollback the rollback
                        self._something_members_to_or_from_groups(member_dn_list, successful_groups, member_lookup_fn,
                                                                  stop_and_rollback_on_error=False, adding=new_op,
                                                                  controls=controls)
                    except MembershipModificationException:
                        logger.error('Failed to completely rollback changes after failure. '
                                     'Halting and raising exception')
                        raise MembershipModificationRollbackException('Failed to modify group with distinguished name {} and rollback of '
                                                                      'successful groups with distinguished names {} failed. Please check '
                                                                      'the current state of those groups in AD before proceeding.'
                                                                      .format(group_dn, successful_groups))
                    logger.info('Successfully rolled back changes to %s', successful_groups)
                    break
                else:
                    logger.warning('Continuing despite failure')
            else:
                successful_groups.append(group_dn)

        # convert our successful groups into the input format before returning them
        original_groups_that_succeeded = [normalized_target_group_dns[group] for group in successful_groups]
        # raise an exception if we failed at all and wanted to stop and rollback
        # if a rollback was requested, then we only reach this point if it succeeds (a rollback exception is raised
        # if it fails), so raise an error declaring what failed and the fact that we rolled back
        if failing_group is not None and stop_and_rollback_on_error:
            raise MembershipModificationException('Failed to successfully update group {} to {} member. Rolled '
                                                  'back changes to other groups.'.format(failing_group, verb))
        return original_groups_that_succeeded

    def add_groups_to_groups(self, groups_to_add: List, groups_to_add_them_to: List,
                             stop_and_rollback_on_error: bool=True, controls: List[Control]=None):
        return self._something_members_to_or_from_groups(groups_to_add, groups_to_add_them_to, self.find_group_by_name,
                                                         stop_and_rollback_on_error, adding=True, controls=controls)

    def add_users_to_groups(self, users_to_add: List, groups_to_add_them_to: List,
                            stop_and_rollback_on_error: bool=True, controls: List[Control]=None):
        return self._something_members_to_or_from_groups(users_to_add, groups_to_add_them_to, self.find_user_by_name,
                                                         stop_and_rollback_on_error, adding=True, controls=controls)

    def remove_groups_from_groups(self, groups_to_remove: List, groups_to_remove_them_from: List,
                                  stop_and_rollback_on_error: bool=True, controls: List[Control]=None):
        return self._something_members_to_or_from_groups(groups_to_remove, groups_to_remove_them_from,
                                                         self.find_group_by_name, stop_and_rollback_on_error,
                                                         adding=False, controls=controls)

    def remove_users_from_groups(self, users_to_remove: List, groups_to_remove_them_from: List,
                                 stop_and_rollback_on_error: bool=True, controls: List[Control]=None):
        return self._something_members_to_or_from_groups(users_to_remove, groups_to_remove_them_from,
                                                         self.find_user_by_name, stop_and_rollback_on_error,
                                                         adding=False, controls=controls)

    # Functions for managing permissions within the domain

    def find_security_descriptor_for_group(self, group, include_sacl: bool=False):
        """ Given a group, find its security descriptor. The security descriptor will be returned as a
        SelfRelativeSecurityDescriptor object.

        :param group: The group for which we will read the security descriptor. This may be an ADGroup object or a
                      string name identifying the group (in which case it will be looked up).
        :param include_sacl: If true, we will attempt to read the System ACL for the group in addition to the
                             Discretionary ACL and owner information when reading the security descriptor. This is
                             more privileged than just getting the Discretionary ACL and owner information.
                             Defaults to False.
        :raises: ObjectNotFoundException if the group cannot be found.
        :raises: InvalidLdapParameterException if the group specified is not a string or an ADGroup object
        :raises: SecurityDescriptorDecodeException if we fail to decode the security descriptor.
        """
        if isinstance(group, str):
            # do one lookup for existence, separate from reading the security descriptor, for better errors
            original = group
            group = self.find_group_by_name(group)
            if group is None:
                raise ObjectNotFoundException('No group could be found with the Group object class and name {}'
                                              .format(original))
        elif not isinstance(group, ADGroup):
            raise InvalidLdapParameterException('The group specified must be an ADGroup object or a string group name.')
        return self.find_security_descriptor_for_object(group, include_sacl=include_sacl)

    def find_security_descriptor_for_user(self, user, include_sacl: bool=False):
        """ Given a user, find its security descriptor. The security descriptor will be returned as a
        SelfRelativeSecurityDescriptor object.

        :param user: The user for which we will read the security descriptor. This may be an ADUser object or a
                     string name identifying the user (in which case it will be looked up).
        :param include_sacl: If true, we will attempt to read the System ACL for the user in addition to the
                             Discretionary ACL and owner information when reading the security descriptor. This is
                             more privileged than just getting the Discretionary ACL and owner information.
                             Defaults to False.
        :raises: ObjectNotFoundException if the user cannot be found.
        :raises: InvalidLdapParameterException if the user specified is not a string or an ADUser object
        :raises: SecurityDescriptorDecodeException if we fail to decode the security descriptor.
        """
        if isinstance(user, str):
            # do one lookup for existence, separate from reading the security descriptor, for better errors
            original = user
            user = self.find_user_by_name(user)
            if user is None:
                raise ObjectNotFoundException('No user could be found with the User object class and name {}'
                                              .format(original))
        elif not isinstance(user, ADUser):
            raise InvalidLdapParameterException('The user specified must be an ADUser object or a string user name.')
        return self.find_security_descriptor_for_object(user, include_sacl=include_sacl)

    def find_security_descriptor_for_object(self, ad_object, include_sacl: bool=False):
        """ Given an object, find its security descriptor. The security descriptor will be returned as a
        SelfRelativeSecurityDescriptor object.

        :param ad_object: The object for which we will read the security descriptor. This may be an ADObject object or a
                          string distinguished identifying the object.
        :param include_sacl: If true, we will attempt to read the System ACL for the object in addition to the
                             Discretionary ACL and owner information when reading the security descriptor. This is
                             more privileged than just getting the Discretionary ACL and owner information.
                             Defaults to False.
        :raises: ObjectNotFoundException if the object cannot be found.
        :raises: InvalidLdapParameterException if the ad_object specified is not a string DN or an ADObject object
        :raises: SecurityDescriptorDecodeException if we fail to decode the security descriptor.
        """
        dn_to_search = None
        if isinstance(ad_object, ADObject):
            dn_to_search = ad_object.distinguished_name
        elif isinstance(ad_object, str):
            dn_to_search = ad_object
            if not ldap_utils.is_dn(ad_object):
                raise InvalidLdapParameterException('The object specified must be an ADObject object or a string '
                                                    'distinguished name.')
            # do one lookup for existence, separate from reading the security descriptor, for better errors
            res = self._find_ad_objects_and_attrs(dn_to_search, ldap_constants.FIND_ANYTHING_FILTER,
                                                  BASE, [], 1, ADObject, None)
            if not res:
                raise ObjectNotFoundException('No object could be found with distinguished name {}'.format(ad_object))

        attrs = [ldap_constants.AD_ATTRIBUTE_SECURITY_DESCRIPTOR]
        controls = sd_utils.get_security_descriptor_read_controls(include_sacl)
        res = self._find_ad_objects_and_attrs(dn_to_search, ldap_constants.FIND_ANYTHING_FILTER,
                                              BASE, attrs, 1, ADObject, controls)
        if not res:
            sacl_str = 'reading the SACL' if include_sacl else 'not reading the SACL'
            raise PermissionDeniedException('Failed to read the security descriptor for object with distinguished name '
                                            '{} when {} due to permission issues.'.format(dn_to_search, sacl_str))
        detailed_ad_obj = res[0]
        security_desc_bytes = detailed_ad_obj.get(ldap_constants.AD_ATTRIBUTE_SECURITY_DESCRIPTOR)
        # 1-item lists sometimes show up in our response. controls can also affect this
        if isinstance(security_desc_bytes, list):
            security_desc_bytes = security_desc_bytes[0]

        security_descriptor = sd_utils.SelfRelativeSecurityDescriptor()
        security_descriptor.parse_structure_from_bytes(security_desc_bytes)
        return security_descriptor

    # Various account management functionalities

    def change_password_for_account(self, account, new_password: str, current_password: str):
        """ Change a password for a user (includes computers) given the new desired password and old desired password.
        When a password is changed, the old password is provided along with the new one, and this significantly reduces
        the permissions needed in order to perform the operation. By default, any user can perform CHANGE_PASSWORD for
        any other user.
        This also avoids invalidating kerberos keys generated by the old password. Their validity will depend on the
        domain's policy regarding old passwords/keys and their allowable use period after change.

        :param account: The account whose password is being changed. This may either be a string account name, to be
                        looked up, or an ADObject object.
        :param current_password: The current password for the account.
        :param new_password: The new password for the account. Technically, if None is specified, then this behaves
                             as a RESET_PASSWORD operation.
        :returns: True if the operation succeeds. If the operation fails, either an exception will be raised or False
                  will be returned depending on whether the ldap connection for this session has "raise_exceptions"
                  set to True or not.
        """
        account_dn = None
        if isinstance(account, ADObject):
            account_dn = account.distinguished_name
        elif isinstance(account, str):
            account_obj = self.find_user_by_name(account)
            if account_obj is None:
                raise ObjectNotFoundException('No account could be found with the User object class and name {}'
                                              .format(account))
            account_dn = account_obj.distinguished_name
        else:
            raise InvalidLdapParameterException('The account specified must either be an ADObject object or a string '
                                                'name.')
        return self.ldap_connection.extend.microsoft.modify_password(account_dn, new_password, current_password)

    def reset_password_for_account(self, account, new_password: str):
        """ Resets a password for a user (includes computers) to a new desired password.
        To reset a password, a new password is provided to replace the current one without providing the current
        password. This is a privileged operation and maps to the RESET_PASSWORD permission in AD.

        :param account: The account whose password is being changed. This may either be a string account name, to be
                        looked up, or an ADObject object.
        :param new_password: The new password for the account.
        :returns: True if the operation succeeds. If the operation fails, either an exception will be raised or False
                  will be returned depending on whether the ldap connection for this session has "raise_exceptions"
                  set to True or not.
        """
        return self.change_password_for_account(account, new_password, None)

    def unlock_account(self, account):
        """ Unlock a user who's been locked out for some period of time.
        :param account: The string name of the user/computer account that has been locked out. This may either be a
                        sAMAccountName, a distinguished name, or a unique common name. This can also be an ADObject,
                        and the distinguished name will be extracted from it.
        :returns: True if the operation succeeds. If the operation fails, either an exception will be raised or False
                  will be returned depending on whether the ldap connection for this session has "raise_exceptions"
                  set to True or not.
        """
        account_dn = None
        if isinstance(account, ADObject):
            account_dn = account.distinguished_name
        elif isinstance(account, str):
            account_obj = self.find_user_by_name(account)
            if account_obj is None:
                raise ObjectNotFoundException('No account could be found with the User object class and name {}'
                                              .format(account))
            account_dn = account_obj.distinguished_name
        else:
            raise InvalidLdapParameterException('The account specified must either be an ADObject object or a string '
                                                'name.')
        return self.ldap_connection.extend.microsoft.unlock_account(account_dn)

    def who_am_i(self):
        """ Return the authorization identity as recognized by the server.
        This can be helpful when a script is provided with an identity in one form that is used to start a session
        (e.g. a distinguished name, or a pre-populated kerberos cache) and then it wants to determine its identity
        that the server actually sees.
        This just calls the LDAP connection function, as it's suitable for AD as well.
        """
        return self.ldap_connection.extend.standard.who_am_i()

    def __repr__(self):
        conn_repr = self.ldap_connection.__repr__()
        domain_repr = self.domain.__repr__()
        return 'ADSession(ldap_connection={}, domain={})'.format(conn_repr, domain_repr)

    def __str__(self):
        return self.__repr__()
