from __future__ import annotations

from ldap3 import (
    BASE,
    Connection,
    SUBTREE,
)
from typing import TYPE_CHECKING
# allow type hinting without creating a circular import
if TYPE_CHECKING:
    from core.ad_domain import ADDomain

import environment.ldap_utils.ldap_format_utils as ldap_utils
import environment.ldap_utils.ldap_constants as ldap_constants
import environment.security_utils.security_config_utils as security_utils
import environment.security_utils.security_config_constants as security_constants

from core.ad_computer import ADComputer


class ADSession:

    def __init__(self, ldap_connection: Connection, domain: ADDomain):
        self.ldap_connection = ldap_connection
        self.domain = domain
        self.domain_dns_name = self.domain.get_domain_dns_name()
        self.domain_search_base = ldap_utils.construct_ldap_base_dn_from_domain(self.domain_dns_name)

    def is_authenticated(self):
        """ Returns if the session is currently authenticated """
        return self.ldap_connection.bound

    def is_open(self):
        """ Returns if the session's connection is currently open """
        return not self.ldap_connection.closed

    def is_encrypted(self):
        """ Returns if the session's connection is encrypted """
        return self.ldap_connection.tls_started or self.ldap_connection.server.ssl

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

    def dn_exists_in_domain(self, distinguished_name):
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
        return self.ldap_connection.search(search_base=search_dn,
                                           search_filter=ldap_constants.FIND_ANYTHING_FILTER,
                                           search_scope=BASE,
                                           size_limit=1)

    def object_exists_in_domain_with_attribute(self, attr, unescaped_value):
        """ Check if any objects exist in the domain with a given attribute. Returns True if so, False otherwise.
        :param attr: The LDAP attribute to examine in the search.
        :param unescaped_value: The value of the attribute that we're looking for, in its raw form.
        :returns: True if any objects exist in the domain with the attribute specified equal to the value.
        """
        if ldap_utils.is_dn(unescaped_value):
            value = ldap_utils.escape_dn_for_filter(unescaped_value)
        else:
            value = ldap_utils.escape_generic_filter_value(unescaped_value)
        ldap_filter = '({}={})'.format(attr, value)
        # search returns True if it finds anything. we only need to find one object before stopping
        return self.ldap_connection.search(search_base=self.domain_search_base,
                                           search_filter=ldap_filter,
                                           search_scope=SUBTREE,
                                           size_limit=1)

    def _create_object(self, object_dn, object_classes, account_attr_dict):
        if self.dn_exists_in_domain(object_dn):
            raise Exception('An object already exists within the domain with distinguished name {} - please remove it '
                            'or change the attributes specified such that a different distinguished name is created.'
                            .format(object_dn))
        success = self.ldap_connection.add(object_dn, object_classes, account_attr_dict)
        if success:
            return success
        # don't include attributes in the exception because a password could be there and it could get logged.
        raise Exception('An exception was encountered creating an object with distinguished name {} and object classes '
                        '{}. LDAP result: {}'.format(object_dn, object_classes, self.ldap_connection.result))

    def create_computer(self, computer_name, computer_location=None, computer_password=None,
                        encryption_types=None, hostnames=None, services=None, supports_legacy_behavior=False,
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
        # validate our computer name and then determine our sAMAccountName
        computer_name = ldap_utils.validate_and_normalize_computer_name(computer_name, supports_legacy_behavior)
        samaccount_name = computer_name + '$'

        if self.object_exists_in_domain_with_attribute(ldap_constants.AD_ATTRIBUTE_SAMACCOUNT_NAME, samaccount_name):
            raise Exception('An object already exists with sAMAccountName {} so a computer may not be created with '
                            'the name {}'.format(samaccount_name, computer_name))

        # get or normalize our computer location. the end format is as a relative distinguished name
        if computer_location is None:
            computer_location = ldap_constants.DEFAULT_COMPUTER_LOCATION
        else:
            computer_location = ldap_utils.normalize_object_location_in_domain(computer_location,
                                                                               self.domain_dns_name)
        # now we can build our full object distinguished name
        computer_dn = ldap_utils.construct_object_distinguished_name(computer_name, computer_location,
                                                                     self.domain_dns_name)
        if self.dn_exists_in_domain(computer_dn):
            raise Exception('There exists an object in the domain with distinguished name {} and so a computer may not '
                            'be created in the domain with name {} in location {}. Please use a different name or '
                            'location.'.format(computer_dn, computer_name, computer_location))

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
                raise Exception('An object exists in the domain with service principal name {} and so creating a '
                                'computer with the hostnames ({}) and services ({}) in use will cause undefined, '
                                'conflicting behavior during lookups. Please specify different hostnames or services, '
                                'or a different computer name if hostnames are not being explicitly set.'
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

        # add in our additional account attributes at the end so they can override anything we set here
        computer_attributes.update(additional_account_attributes)

        self._create_object(computer_dn, ldap_constants.OBJECT_CLASSES_FOR_COMPUTER, computer_attributes)
        return ADComputer(samaccount_name, self.domain, computer_location, computer_password, spns,
                          encryption_types)

    def take_over_existing_computer(self, computer_name):
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

    def create_user(self):
        raise NotImplementedError()

    def find_user(self):
        raise NotImplementedError()

    def create_group(self):
        raise NotImplementedError()

    def find_group(self):
        raise NotImplementedError()

    def find_groups_for_user(self):
        raise NotImplementedError()

    def find_groups_for_group(self):
        raise NotImplementedError()
