""" A class defining a session with an AD domain and the functionality it offers. """

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
import re
import socket
import ssl
import time

from datetime import datetime
from ldap3 import (
    BASE,
    Connection,
    LEVEL,
    MODIFY_ADD,
    MODIFY_REPLACE,
    SIMPLE,
    SUBTREE,
)
from ldap3.protocol.rfc4511 import Control
from typing import Dict, List, Optional, Union, TYPE_CHECKING

if TYPE_CHECKING:
    from ms_active_directory.core.ad_domain import ADDomain, ADTrustedDomain

import ms_active_directory.environment.constants as constants
import ms_active_directory.environment.ldap.ldap_format_utils as ldap_utils
import ms_active_directory.environment.ldap.ldap_constants as ldap_constants
import ms_active_directory.environment.security.security_config_utils as security_utils
import ms_active_directory.environment.security.security_config_constants as security_constants
import ms_active_directory.environment.security.security_descriptor_utils as sd_utils

from ms_active_directory import logging_utils
from ms_active_directory.core.managed_ad_objects import ManagedADComputer
from ms_active_directory.core.ad_objects import (
    ADComputer,
    ADGroup,
    ADGroupPolicy,
    ADUser,
    ADObject,
    cast_ad_object_to_specific_object_type,
)
from ms_active_directory.environment.constants import ADFunctionalLevel, ADVersion
from ms_active_directory.environment.security.ad_security_guids import ADRightsGuid
from ms_active_directory.exceptions import (
    AttributeModificationException,
    DomainJoinException,
    DomainSearchException,
    DuplicateNameException,
    InvalidLdapParameterException,
    MembershipModificationException,
    MembershipModificationRollbackException,
    ObjectCreationException,
    ObjectNotFoundException,
    PermissionDeniedException,
    SessionTransferException,
)

logger = logging_utils.get_logger()


class ADSession:

    def __init__(self, ldap_connection: Connection, domain: 'ADDomain', search_paging_size: int = 100,
                 trusted_domain_cache_lifetime_seconds: int = 24 * 60 * 60):
        """ Create a session object for a connection to an AD domain.
        Given an LDAP connection, a domain, and optional parameters relating to searches and multi-domain
        functionality, create an ADSession object.

        :param ldap_connection: An ldap3 Connection object representing the connection to LDAP servers within
                                the domain.
        :param domain: An ADDomain object representing the domain that we're communicating with.
        :param search_paging_size: Optional. The page size for paginated searches. If a search is expected to
                                   be able to have more than this many results, a paginated search will be
                                   performed. This is used as the page size in such searches. Changing this
                                   affects the balance between the number of queries made and the size of
                                   each query response in a large scale environment, and so it can be used
                                   to optimize behavior based on network topology and traffic.
                                   If not specified, defaults to 100.
        :param trusted_domain_cache_lifetime_seconds: Optional. How long to maintain our trusted domain cache in
                                                      seconds. The cache of trusted domain information exists because
                                                      trust relationships change infrequently, but will be used a lot
                                                      in searches and such when automatic traversal of trusts is
                                                      supported. Can be set to 0 to disable the cache.
                                                      If not specified, defaults to 24 hours.
        """
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
        # this is how often we'll re-read trusted domain information, since it doesn't change often and might be
        # used across A LOT of queries, so we want to cut back on the query load for trusted domain info.
        self.trusted_domain_cache_lifetime_seconds = trusted_domain_cache_lifetime_seconds
        self._trusted_domain_list_cache = []
        self._last_trusted_domain_query_time = None

    def is_authenticated(self) -> bool:
        """ Returns if the session is currently authenticated """
        return self.ldap_connection.bound

    def is_encrypted(self) -> bool:
        """ Returns if the session's connection is encrypted """
        return self.ldap_connection.tls_started or self.ldap_connection.server.ssl

    def is_open(self) -> bool:
        """ Returns if the session's connection is currently open """
        return not self.ldap_connection.closed

    def is_thread_safe(self) -> bool:
        """ Returns if the session's connection is thread-safe """
        return self.ldap_connection.strategy.thread_safe

    def get_ldap_connection(self) -> Connection:
        """ Returns the LDAP connection that this session uses for communication.
        This is particularly useful if a user wants to make complex LDAP queries or perform
        operations that are not supported by the ADSession object, and is willing to craft
        them and parse results themselves.
        """
        return self.ldap_connection

    def get_current_server_uri(self) -> str:
        """ Returns the URI of the server that this session is currently communicating with """
        return self.ldap_connection.server.name

    def get_domain(self) -> 'ADDomain':
        """ Returns the domain that this session is connected to """
        return self.domain

    def get_domain_dns_name(self) -> str:
        """ Returns the domain that this session is connected to """
        return self.domain_dns_name

    def get_domain_search_base(self) -> str:
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

    def get_search_paging_size(self) -> int:
        return self.search_paging_size

    def set_search_paging_size(self, new_size: int):
        self.search_paging_size = new_size

    def get_trusted_domain_cache_lifetime_seconds(self) -> int:
        return self.trusted_domain_cache_lifetime_seconds

    def set_trusted_domain_cache_lifetime_seconds(self, new_lifetime_in_seconds: int):
        self.trusted_domain_cache_lifetime_seconds = new_lifetime_in_seconds

    def dn_exists_in_domain(self, distinguished_name: str) -> bool:
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
        exists, result, _, _ = ldap_utils.process_ldap3_conn_return_value(self.ldap_connection, res)
        # no such object should be considered an okay search
        search_err = result['result'] != 0 and result['result'] != ldap_constants.NO_SUCH_OBJECT
        if search_err:
            raise DomainSearchException('An error was encountered searching the domain to determine if {} exists. '
                                        'This may have occurred due to domain unavailability or a permission '
                                        'issue. Raw result: {}'.format(distinguished_name, result))
        return exists

    def object_exists_in_domain_with_attribute(self, attr: str, unescaped_value: str) -> bool:
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
        _, result, response, _ = ldap_utils.process_ldap3_conn_return_value(self.ldap_connection, res)
        # no such object should be considered an okay search
        search_err = result['result'] != 0 and result['result'] != ldap_constants.NO_SUCH_OBJECT
        if search_err:
            raise DomainSearchException('An error was encountered searching the domain to determine if an object '
                                        'exists with value {} for attribute {}. This may have occurred due to domain '
                                        'unavailability or a permission issue. Raw result: {}'
                                        .format(attr, unescaped_value, result))
        real_entities = ldap_utils.remove_ad_search_refs(response)
        return len(real_entities) > 0

    def _create_object(self, object_dn: str, object_classes: List[str], account_attr_dict: dict,
                       sanity_check_for_existence: bool = True):
        if sanity_check_for_existence and self.dn_exists_in_domain(object_dn):
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
                                      'and object classes {}. LDAP result: {}'.format(object_dn, object_classes,
                                                                                      result))

    def create_computer(self, computer_name: str, computer_location: str = None, computer_password: str = None,
                        encryption_types: List[Union[str, security_constants.ADEncryptionType]] = None,
                        hostnames: List[str] = None, services: List[str] = None, supports_legacy_behavior: bool = False,
                        **additional_account_attributes) -> ManagedADComputer:
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
                                              keyword arguments in order to avoid over-complication, since most
                                              people won't set them (e.g. userAccountControl).
        :returns: an ManagedADComputer object representing the computer.
        :raises: DomainJoinException if any of our validation of the specified attributes fails or if anything
                 specified conflicts with objects in the domain.
        :raises: ObjectCreationException if we fail to create the computer for a reason unrelated to what we can
                 easily validate in advance (e.g. permission issue)
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
            raise DomainJoinException('An object already exists with sAMAccountName {} so a computer may not be '
                                      'created with the name {}'.format(samaccount_name, computer_name))

        # get or normalize our computer location. the end format is as a relative distinguished name
        if computer_location is None:
            computer_location = ldap_constants.DEFAULT_COMPUTER_LOCATION
        else:
            computer_location = ldap_utils.normalize_object_location_in_domain(computer_location,
                                                                               self.domain_dns_name)
            # make sure our location exists
            if ldap_utils.is_dn(computer_location):
                location_obj = self.find_object_by_distinguished_name(computer_location)
            else:
                location_obj = self.find_object_by_canonical_name(computer_location)
            if location_obj is None:
                raise DomainJoinException('The computer location {} cannot be found in the domain.'
                                          .format(computer_location))
            # make sure our location is a container
            is_container_or_ou = (location_obj.is_of_object_class(ldap_constants.ORGANIZATIONAL_UNIT_OBJECT_CLASS)
                                  or location_obj.is_of_object_class(ldap_constants.CONTAINER_OBJECT_CLASS))
            if not is_container_or_ou:
                raise DomainJoinException('The specified computer location {} exists, but is not a container or an '
                                          'organizational unit, and so a computer cannot be created there.')
            # make sure that going forward we have an LDAP-style relative distinguished name for our
            # location
            computer_location = ldap_utils.normalize_object_location_in_domain(location_obj.distinguished_name,
                                                                               self.domain_dns_name)

        # now we can build our full object distinguished name
        computer_dn = ldap_utils.construct_object_distinguished_name(computer_name, computer_location,
                                                                     self.domain_dns_name)
        if self.dn_exists_in_domain(computer_dn):
            raise DomainJoinException('There exists an object in the domain with distinguished name {} and so a '
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
                raise DomainJoinException('An object exists in the domain with service principal name {} and so '
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
        logger.info(
            'Attempting to create computer in domain %s with the following LDAP attributes: %s and %s additional '
            'attributes', loggable_attributes, len(additional_account_attributes))

        # add in our additional account attributes at the end so they can override anything we set here
        computer_attributes.update(additional_account_attributes)

        self._create_object(computer_dn, ldap_constants.OBJECT_CLASSES_FOR_COMPUTER, computer_attributes,
                            sanity_check_for_existence=False)  # we already checked for this
        return ManagedADComputer(samaccount_name, self.domain, computer_location, computer_password, spns,
                                 encryption_types)

    def take_over_existing_computer(self, computer: Union[ManagedADComputer, ADObject, str],
                                    computer_password: str = None,
                                    old_computer_password: str = None) -> ManagedADComputer:
        """ Use the session to take over a computer in the domain and return a computer object.
        This resets the computer's password so that nobody else can impersonate it, and reads
        the computer's attributes in order to create a computer object and return it.
        :param computer: This can be an ManagedADComputer or ADObject object representing the computer that should be
                         taken over, or a string identifier for the computer.  If it is a string, it should be
                         the common name or sAMAccountName of the computer to find in the AD domain, or it can be
                         the distinguished name of a computer object.
                         If it appears to be a common name, not ending in $, a sAMAccountName will
                         be derived to search for. If that cannot be found, then a search will be
                         done for this as a common name. If no unique computer can be found with that
                         search, then an exception will be raised.
        :param computer_password: The password to be set for the computer. This is particularly
                                  useful to specify if the computer will be shared across multiple
                                  applications or devices, or if pre-creating a computer for another
                                  application to use. If not specified, a random 120 character
                                  password will be generated.
        :param old_computer_password: The current password for the computer. This is used to reduce the level of
                                      permissions needed for the takeover operation.
        :returns: an ManagedADComputer object representing the computer.
        :raises: DomainJoinException if any of our validation of the specified attributes fails or if anything
                 specified conflicts with objects in the domain.
        :raises: ObjectNotFoundException if a computer cannot be found based on the name specified.
        """
        attributes_to_retrieve = [ldap_constants.AD_ATTRIBUTE_ENCRYPTION_TYPES,  # for key generation and validation
                                  ldap_constants.AD_ATTRIBUTE_SAMACCOUNT_NAME,  # for key generation and identity
                                  ldap_constants.AD_ATTRIBUTE_SERVICE_PRINCIPAL_NAMES,  # for key generation
                                  ldap_constants.AD_ATTRIBUTE_USER_ACCOUNT_CONTROL,  # for validation
                                  ldap_constants.AD_ATTRIBUTE_KVNO]  # for key generation
        # if we got an object, we don't know that it has all the attributes we need, so redo the lookup
        if isinstance(computer, ADObject):
            computer = computer.distinguished_name
        elif isinstance(computer, ManagedADComputer):
            computer = computer.get_samaccount_name()

        # at this point, if we don't have a string, then an invalid type was specified
        if not isinstance(computer, str):
            raise InvalidLdapParameterException(
                'The specified computer must either be an ManagedADComputer object or an '
                'ADObject object representing the computer, or a string identifier for '
                'the computer.')

        computer_obj = None
        # if we got a dn, look it up and make sure it's a computer. otherwise, try to look
        if isinstance(computer, str) and ldap_utils.is_dn(computer):
            computer_objs = self._find_ad_objects_and_attrs(computer, ldap_constants.FIND_COMPUTER_FILTER,
                                                            BASE, attributes_to_retrieve, 1, ADObject)
            if not computer_objs:
                raise ObjectNotFoundException('No computer could be found with the Computer object class and '
                                              'distinguished name {}'.format(computer))
            logger.info('Found computer to takeover using distinguished name %s', computer)
            computer_obj = computer_objs[0]
        elif isinstance(computer, str):
            # try to find a computer with computer_name as its sAMAccountName
            guessed_samaccount_name = computer
            if not computer.endswith('$'):
                guessed_samaccount_name += '$'
            # try our computer name as specified first, since you don't technically NEED computers to end with a $
            for sam in [computer, guessed_samaccount_name]:
                computer_objs = self.find_objects_with_attribute(ldap_constants.AD_ATTRIBUTE_SAMACCOUNT_NAME,
                                                                 sam, attributes_to_retrieve, size_limit=1,
                                                                 object_class=ldap_constants.COMPUTER_OBJECT_CLASS,
                                                                 return_type=ADObject)
                logger.info('Found %s computer results to take over looking up sAMAccountName %s',
                            len(computer_objs), sam)
                if computer_objs:
                    computer_obj = computer_objs[0]
                    break
            # try to use computer_name as a common name
            if computer_obj is None:
                computer_objs = self.find_objects_with_attribute(ldap_constants.AD_ATTRIBUTE_COMMON_NAME,
                                                                 computer, attributes_to_retrieve,
                                                                 object_class=ldap_constants.COMPUTER_OBJECT_CLASS,
                                                                 return_type=ADObject)
                logger.info('Found %s computer results to take over looking up common name %s',
                            len(computer_objs), computer)
                if len(computer_objs) == 0:
                    raise ObjectNotFoundException('No computer could be found with the Computer object class that '
                                                  'possesses either a common name of {}, or a sAMAccountName of {} or '
                                                  '{}'.format(computer, computer, guessed_samaccount_name))
                if len(computer_objs) > 1:
                    raise DuplicateNameException('No computer could be found with the Computer object class that '
                                                 'possesses a sAMAccountName of {} or {} - but multiple computers were '
                                                 'found with the common name {}. Please specify the sAMAccountName of '
                                                 'the computer you wish to take over, or its distinguished name.'
                                                 .format(computer, guessed_samaccount_name, computer))
                computer_obj = computer_objs[0]

        spns = computer_obj.get(ldap_constants.AD_ATTRIBUTE_SERVICE_PRINCIPAL_NAMES)
        enc_type_value = int(computer_obj.get(ldap_constants.AD_ATTRIBUTE_ENCRYPTION_TYPES))
        samaccount_name = computer_obj.get(ldap_constants.AD_ATTRIBUTE_SAMACCOUNT_NAME)
        encryption_types = security_utils.get_supported_encryption_type_enums_from_value(enc_type_value)
        acct_control = int(computer_obj.get(ldap_constants.AD_ATTRIBUTE_USER_ACCOUNT_CONTROL))
        kvno = int(computer_obj.get(ldap_constants.AD_ATTRIBUTE_KVNO))
        computer_location = computer_obj.location

        # validate our encryption types and user account control
        unsupported = [enc_type.name for enc_type in encryption_types if
                       enc_type in security_constants.UNSUPPORTED_ENC_TYPES]
        if unsupported:
            raise DomainJoinException('The following unsupported encryption types were found to be enabled on the '
                                      'computer specified to be taken over: {}'.format(', '.join(unsupported)))
        if acct_control != ldap_constants.COMPUTER_ACCESS_CONTROL_VAL:
            raise DomainJoinException('Currently, it is only supported to take over computers with the account control '
                                      '{}, indicating a workstation trust account with a non-expiring password. The '
                                      'control seen on the computer specified to be taken over was {}.'
                                      .format(ldap_constants.COMPUTER_ACCESS_CONTROL_VAL, acct_control))

        # reset the account password
        if computer_password is None:
            logger.info('Generating random AD password for %s during account takeover', samaccount_name)
            computer_password = security_utils.generate_random_ad_password()

        if old_computer_password is not None:
            success = self.change_password_for_account(computer_obj, computer_password, old_computer_password)
            if not success:
                raise DomainJoinException('Failed to change the password on the computer account. Please check the '
                                          'old password specified for correctness, and ensure that the user being '
                                          'used for this takeover operation has the CHANGE PASSWORD permission on '
                                          'the computer.')
        else:
            success = self.reset_password_for_account(computer_obj, computer_password)
            if not success:
                raise DomainJoinException('Failed to reset the password on the computer account. Please check the '
                                          'permissions of the user being used for this takeover operation and ensure '
                                          'they have the RESET PASSWORD permission, or provide the current computer '
                                          'password for takeover.')
        logger.info('Incrementing kvno from %s to %s after successful password update for %s',
                    kvno, kvno + 1, samaccount_name)
        kvno += 1

        logger.info('Successfully took over computer with sAMAccountName %s', samaccount_name)
        return ManagedADComputer(samaccount_name, self.domain, computer_location, computer_password, spns,
                                 encryption_types, kvno=kvno)

    # FUNCTIONS FOR FINDING DOMAIN INFORMATION

    def is_domain_close_in_time_to_localhost(self, allowed_drift_seconds=None) -> bool:
        """ Get whether the domain time is close to the current local time.
        Just calls the parent domain function and returns that. This is included here for completeness.
        :param allowed_drift_seconds: The number of seconds considered "close", defaults to 5 minutes.
                                      5 minutes is the standard allowable drift for kerberos.
        :returns: A boolean indicating whether we're within allowed_drift_seconds seconds of the domain time.
        """
        return self.domain.is_close_in_time_to_localhost(self.ldap_connection, allowed_drift_seconds)

    def find_certificate_authorities_for_domain(self, pem_format: bool = True,
                                                controls: List[Control] = None) -> Union[List[str], List[bytes]]:
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
        success, result, entities, _ = ldap_utils.process_ldap3_conn_return_value(self.ldap_connection, res)
        search_err = result['result'] != 0 and result['result'] != ldap_constants.NO_SUCH_OBJECT
        if search_err:
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

    def find_current_time_for_domain(self) -> datetime:
        """ Get the current time for the domain as a datetime object.
        Just calls the parent domain function and returns that. This is included here for completeness.
        :returns: A datetime object representing the current time in the domain.
        """
        return self.domain.find_current_time(self.ldap_connection)

    def find_dns_servers_for_domain(self, controls: List[Control] = None) -> Dict[str, str]:
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
        success, result, entities, _ = ldap_utils.process_ldap3_conn_return_value(self.ldap_connection, res)
        search_err = result['result'] != 0 and result['result'] != ldap_constants.NO_SUCH_OBJECT
        if search_err:
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

    def find_forest_schema_version(self) -> ADVersion:
        """ Attempt to determine the version of Windows Server set in the forest's schema.
        :returns: An Enum of type ADVersion indicating the schema version.
        """
        search_loc = '{},{}'.format(ldap_constants.DOMAIN_CONTROLLER_SCHEMA_VERSION_SEARCH_CONTAINER,
                                    self.domain_search_base)
        res = self.ldap_connection.search(search_base=search_loc, search_filter=ldap_constants.FIND_ANYTHING_FILTER,
                                          search_scope=BASE,
                                          attributes=[ldap_constants.AD_ATTRIBUTE_GET_ALL_NON_VIRTUAL_ATTRS],
                                          size_limit=1)
        success, result, entities, _ = ldap_utils.process_ldap3_conn_return_value(self.ldap_connection, res)
        search_err = result['result'] != 0
        if search_err:
            raise DomainSearchException('Failed to search domain for schema.')
        entities = ldap_utils.remove_ad_search_refs(entities)
        if len(entities) == 0:
            raise DomainSearchException('The forest schema could not be found when searching the domain.')
        schema = entities[0]
        ad_schema_ver = schema['attributes'][ldap_constants.AD_SCHEMA_VERSION]
        return constants.ADVersion.get_version_from_schema_number(ad_schema_ver)

    def find_functional_level_for_domain(self) -> ADFunctionalLevel:
        """ Attempt to discover the functional level of the domain and return it.
        This will indicate if the domain is operating at the level of a 2008, 2012R2, 2016, etc. domain.
        The functional level of a domain influences what functionality exists (e.g. 2003 cannot issue AES keys,
        2012 cannot use many TLS ciphers introduced with TLS1.3) and so it can be useful for determining what
        to do.
        :returns: An Enum of type ADFunctionalLevel indicating the functional level.
        """
        return self.domain.find_functional_level(self.ldap_connection)

    def find_netbios_name_for_domain(self, force_refresh: bool = False) -> str:
        """ Find the netbios name for this domain. Renaming a domain is a huge task and is incredibly rare,
        so this information is cached when first read, and it only re-read if specifically requested.

        :param force_refresh: If set to true, the domain will be searched for the information even if
                              it is already cached. Defaults to false.
        :returns: A string indicating the netbios name of the domain.
        """
        return self.domain.find_netbios_name(self.ldap_connection, force_refresh)
        pass

    def find_policies_in_domain(self) -> List[ADGroupPolicy]:
        """ Find all of the policy objects in this domain. The number of policies is often less than the
        number of things affected by them, so querying all of them once and handling mapping locally is
        more desirable than re-querying policies every time a container that bears policies is queried.

        :returns: A list of ADGroupPolicy objects representing the policies in the domain.
        """
        policy_loc = ldap_constants.DOMAIN_POLICIES_CONTAINER + ',' + self._domain_validation_search_base
        # search for things with the policy object class in the relevant container
        policies = self.find_objects_with_attribute(ldap_constants.AD_ATTRIBUTE_OBJECT_CLASS,
                                                    ldap_constants.GROUP_POLICY_CONTAINER_CLASS,
                                                    attributes_to_lookup=['*'],
                                                    object_class=ldap_constants.GROUP_POLICY_CONTAINER_CLASS,
                                                    return_type=ADGroupPolicy,
                                                    search_base=policy_loc)
        return policies

    def find_supported_sasl_mechanisms_for_domain(self) -> List[str]:
        """ Attempt to discover the SASL mechanisms supported by the domain and return them.
        This just builds upon the functionality that the domain has for this, as you don't need
        to be authenticated as anything other than anonymous to read this information (since it's
        often used to figure out how to authenticate).
        This is included in the session object for completeness.
        :returns: A list of strings indicating the supported SASL mechanisms for the domain.
                  ex: ['GSSAPI', 'GSS-SPNEGO', 'EXTERNAL']
        """
        return self.domain.find_supported_sasl_mechanisms(self.ldap_connection)

    def find_trusted_domains_for_domain(self, force_cache_refresh=False) -> List['ADTrustedDomain']:
        """ Find the trusted domains for this domain.
        If we have cached trusted domains for this session's domain, and the cache is still valid based on our
        cache lifetime, return that.

        :param force_cache_refresh: If true, don't use our cached trusted domains even if the cache is valid.
                                    Defaults to false.
        :returns: A list of ADTrustedDomain objects
        """
        if (not force_cache_refresh) and self._last_trusted_domain_query_time is not None:
            now = time.time()
            # if the current time predates our last refresh time, then time has been reconfigured on the local system
            # since we last queried trusted domains. this might have been done to correct issues in kerberos auth, or
            # unrelated, but either way if time moves in the wrong direction we consider our cache invalid.
            # if time is moving forwards, then check if it's moved forward more than our lifetime in seconds, and if not
            # return a copy of our cache
            if (self._last_trusted_domain_query_time <= now and
                    now - self._last_trusted_domain_query_time >= self.trusted_domain_cache_lifetime_seconds):
                # return a shallow copy so that if someone (for example) filters out MIT-type trusts,
                # it won't affect our cache
                return copy.copy(self._trusted_domain_list_cache)
        else:
            now = time.time()

        trusted_domains = self.domain.find_trusted_domains(self.ldap_connection)
        # keep a shallow copy so that if someone (for example) filters out MIT-type trusts,
        # it won't affect our cache
        self._trusted_domain_list_cache = copy.copy(trusted_domains)
        self._last_trusted_domain_query_time = now
        return trusted_domains

    # FUNCTIONS FOR FINDING USERS AND GROUPS

    def _find_ad_objects_and_attrs(self, search_base: str, search_filter: str, search_scope: str,
                                   attributes: List[str], size_limit: int, return_type, controls: List[Control] = None):
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
        _, result, resp, _ = ldap_utils.process_ldap3_conn_return_value(self.ldap_connection, res,
                                                                        paginated_response=paginate)
        search_err = result['result'] != 0 and result['result'] != ldap_constants.NO_SUCH_OBJECT
        if search_err:
            raise DomainSearchException('An error was encountered searching the domain; this may be due to a '
                                        'permission issue or an domain resource availability issue. Raw '
                                        'response: {}'.format(result))
        resp = ldap_utils.remove_ad_search_refs(resp)
        if not resp:
            return []

        results = []
        for entry in resp:
            entry_attributes = entry['attributes']
            obj = return_type(entry['dn'], entry_attributes, self.domain)
            results.append(obj)
        return results

    def find_objects_with_attribute(self, attribute_name: str, attribute_value, attributes_to_lookup: List[str] = None,
                                    size_limit: int = 0, object_class: str = None, return_type=None,
                                    controls: List[Control] = None, search_base: str = None) -> List[Union[ADUser,
                                                                                                           ADComputer,
                                                                                                           ADObject,
                                                                                                           ADGroup,
                                                                                                           ADGroupPolicy]]:
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
        :param search_base: An alternate search base to use. If not specified, defaults to the session's domain
                            search base.
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
        if search_base is None:
            search_base = self.domain_search_base
        # a size limit of 0 means unlimited
        res = self._find_ad_objects_and_attrs(search_base, search_filter, SUBTREE,
                                              attributes_to_lookup, size_limit, return_type, controls)
        logger.info('%s %s objects found with %s value %s', len(res), object_class, attribute_name, attribute_value)
        return res

    def find_groups_by_attribute(self, attribute_name: str, attribute_value, attributes_to_lookup: List[str] = None,
                                 size_limit: int = 0, controls: List[Control] = None) -> List[ADGroup]:
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

    def find_groups_by_common_name(self, group_name: str, attributes_to_lookup: List[str] = None,
                                   controls: List[Control] = None) -> List[ADGroup]:
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

    def find_group_by_distinguished_name(self, group_dn: str, attributes_to_lookup: List[str] = None,
                                         controls: List[Control] = None) -> Optional[ADGroup]:
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

    def find_group_by_sam_name(self, group_name: str, attributes_to_lookup: List[str] = None,
                               controls: List[Control] = None) -> Optional[ADGroup]:
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
        search_filter = '(&({sam_attr}={sam_name}){type_filter})'.format(
            sam_attr=ldap_constants.AD_ATTRIBUTE_SAMACCOUNT_NAME,
            sam_name=group_name,
            type_filter=ldap_constants.FIND_GROUP_FILTER)
        res = self._find_ad_objects_and_attrs(self.domain_search_base, search_filter, SUBTREE,
                                              attributes_to_lookup, 1, ADGroup, controls)
        if not res:
            return None
        return res[0]

    def find_group_by_sid(self, group_sid: Union[security_constants.WellKnownSID, str, sd_utils.ObjectSid],
                          attributes_to_lookup: List[str] = None, controls: List[Control] = None) -> Optional[ADGroup]:
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

    def find_group_by_name(self, group_name: str, attributes_to_lookup: List[str] = None,
                           controls: List[Control] = None) -> Optional[ADGroup]:
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
        return self._find_by_name_common(group_name, attributes_to_lookup, ADGroup, controls=controls)

    def find_object_by_sid(self, sid: Union[security_constants.WellKnownSID, str, sd_utils.ObjectSid],
                           attributes_to_lookup: List[str] = None, object_class: str = None,
                           return_type=None, controls: List[Control] = None) -> Optional[Union[ADObject, ADUser,
                                                                                               ADGroup, ADComputer]]:
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
            return cast_ad_object_to_specific_object_type(results[0])
        return None

    def find_object_by_canonical_name(self, canonical_name: str, attributes_to_lookup: List[str] = None,
                                      controls: List[Control] = None) -> Optional[Union[ADObject, ADUser, ADGroup,
                                                                                        ADComputer]]:
        """ Find an object in the domain using a canonical name, also called a 'windows path style' name.

        :param canonical_name: A windows path style name representing an object in the domain. This may be either a
                               fully canonical name (e.g. example.com/Users/Administrator) or a relative canonical
                               name (e.g. /Users/Administrator).
        :param attributes_to_lookup: Attributes to look up about the object. Regardless of what's specified,
                                     the object's name and object class attributes will be queried.
        :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                         whether or not certain properties/attributes are critical, which influences whether a search
                         may succeed or fail based on their availability.
        :returns: an ADObject object or None if the distinguished name does not exist. If the object can be cast to
                  a more specific subclass, like ADUser, then it will be.
        """
        if ldap_utils.is_dn(canonical_name):
            raise InvalidLdapParameterException('{} is not in the format of a windows canonical name. Example: '
                                                'example.com/Users/Admins'.format(canonical_name))
        normalized_canonical_name = ldap_utils.normalize_object_location_in_domain(canonical_name,
                                                                                   self.domain_dns_name)
        # you cannot search by canonical name because it's a constructed attribute.
        # so instead we do once search at each level, building our way down until we either
        # hit a level where a piece is missing, or until we find the full distinguished name version
        # of the windows path name
        name_pieces = re.split(r'(?<!\\)/', normalized_canonical_name)  # split on unescaped / characters
        # replace escaped forward slashes with unescaped forward slashes because forward slashes are not
        # escaped in distinguished names
        name_pieces = [piece.replace('\\/', '/') for piece in name_pieces]
        num_pieces = len(name_pieces)
        ad_obj = None
        if num_pieces == 0:
            return None
        logger.info('Split windows style path into %s pieces to conduct search', num_pieces)
        current_location = self._domain_validation_search_base
        for index, piece in enumerate(name_pieces):
            escaped_piece_name = ldap_utils.escape_generic_filter_value(piece)
            logger.info('Searching for %s within %s', escaped_piece_name, current_location)
            # use name instead of common name in order to work for OUs and Containers
            to_find = '({}={})'.format(ldap_constants.AD_ATTRIBUTE_NAME, escaped_piece_name)
            attrs = []
            if index == num_pieces - 1:  # last object, get the attributes
                attrs = attributes_to_lookup
            ad_objs = self._find_ad_objects_and_attrs(current_location, to_find, LEVEL,
                                                      attrs, 1, ADObject, controls=controls)
            if not ad_objs:
                return None
            ad_obj = ad_objs[0]
            current_location = ad_obj.distinguished_name
        return cast_ad_object_to_specific_object_type(ad_obj)

    def find_object_by_distinguished_name(self, distinguished_name: str, attributes_to_lookup: List[str] = None,
                                          controls: List[Control] = None) -> Optional[Union[ADObject, ADUser, ADGroup,
                                                                                            ADComputer]]:
        """ Find an object in the domain using a relative distinguished name or full distinguished name.

        :param distinguished_name: A relative or absolute distinguished name within the domain to look up.
        :param attributes_to_lookup: Attributes to look up about the object. Regardless of what's specified,
                                     the object's name and object class attributes will be queried.
        :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                         whether or not certain properties/attributes are critical, which influences whether a search
                         may succeed or fail based on their availability.
        :returns: an ADObject object or None if the distinguished name does not exist. If the object can be cast to
                  a more specific subclass, like ADUser, then it will be.
        """
        if not ldap_utils.is_dn(distinguished_name):
            raise InvalidLdapParameterException('{} does not comply with the format of an LDAP distinguished name.'
                                                .format(distinguished_name))
        # if we have a full distinguished name down to the DC= then don't include our domain search base.
        # otherwise we've got an RDN and should look in the session's configured search base
        if not distinguished_name.lower().endswith(self._domain_validation_search_base.lower()):
            distinguished_name = distinguished_name + ',' + self.domain_search_base
        ad_objs = self._find_ad_objects_and_attrs(distinguished_name, ldap_constants.FIND_ANYTHING_FILTER,
                                                  BASE, attributes_to_lookup, 1, ADObject, controls=controls)
        if not ad_objs:
            return None
        ad_obj = ad_objs[0]
        return cast_ad_object_to_specific_object_type(ad_obj)

    def find_computers_by_attribute(self, attribute_name: str, attribute_value, attributes_to_lookup: List[str] = None,
                                    size_limit: int = 0, controls: List[Control] = None) -> List[ADComputer]:
        """ Find all computers that possess the specified attribute with the specified value, and return a list of
        ADComputer objects.

        :param attribute_name: The LDAP name of the attribute to be used in the search.
        :param attribute_value: The value that returned computers should possess for the attribute.
        :param attributes_to_lookup: A list of additional LDAP attributes to query for the computers. Regardless of
                                     what's specified, the computers' name and object class attributes will be queried.
        :param size_limit: An integer indicating a limit to place the number of results the search will return.
                           If not specified, defaults to 0, meaning unlimited.
        :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                         whether or not certain properties/attributes are critical, which influences whether a search
                         may succeed or fail based on their availability.
        :returns: a list of ADComputer objects representing computers with the specified value for the specified
                  attribute.
        """
        return self.find_objects_with_attribute(attribute_name, attribute_value, attributes_to_lookup, size_limit,
                                                ldap_constants.COMPUTER_OBJECT_CLASS, ADComputer, controls)

    def find_computers_by_common_name(self, computer_name: str, attributes_to_lookup: List[str] = None,
                                      controls: List[Control] = None) -> List[ADComputer]:
        """ Find all computers with a given common name and return a list of ADComputer objects.
        This is particularly useful when you have multiple computers with the same name in different OUs
        as a result of a migration, and want to find them so you can combine them.

        :param computer_name: The common name of the computer(s) to be looked up.
        :param attributes_to_lookup: A list of additional LDAP attributes to query for the computers. Regardless of
                                     what's specified, the computers' name and object class attributes will be queried.
        :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                         whether or not certain properties/attributes are critical, which influences whether a search
                         may succeed or fail based on their availability.
        :returns: a list of ADComputer objects representing computers with the specified common name.
        """
        # build a compound filter for users with this common name
        search_filter = '(&({cn_attr}={cn}){type_filter})'.format(cn_attr=ldap_constants.AD_ATTRIBUTE_COMMON_NAME,
                                                                  cn=computer_name,
                                                                  type_filter=ldap_constants.FIND_COMPUTER_FILTER)
        # a size limit of 0 means unlimited
        res = self._find_ad_objects_and_attrs(self.domain_search_base, search_filter, SUBTREE,
                                              attributes_to_lookup, 0, ADComputer, controls)
        logger.info('%s computers found with common name %s', len(res), computer_name)
        return res

    def find_computer_by_distinguished_name(self, computer_dn: str, attributes_to_lookup: List[str] = None,
                                            controls: List[Control] = None) -> Optional[ADComputer]:
        """ Find a Computer in AD based on a specified distinguished name and return it along with any
        requested attributes.
        :param computer_dn: The distinguished name of the computer.
        :param attributes_to_lookup: A list of additional LDAP attributes to query for the computer. Regardless of
                                     what's specified, the computer's name and object class attributes will be queried.
        :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                         whether or not certain properties/attributes are critical, which influences whether a search
                         may succeed or fail based on their availability.
        :returns: an ADComputer object or None if the computer does not exist.
        """
        # since the distinguished name may be a relative distinguished name or complete one,
        # normalize it
        normalized_rdn = ldap_utils.normalize_object_location_in_domain(computer_dn,
                                                                        self.domain_dns_name)
        search_dn = normalized_rdn + ',' + self.domain_search_base
        res = self._find_ad_objects_and_attrs(search_dn, ldap_constants.FIND_COMPUTER_FILTER, BASE,
                                              attributes_to_lookup, 1, ADComputer, controls)
        if not res:
            return None
        return res[0]

    def find_computer_by_sam_name(self, computer_name: str, attributes_to_lookup: List[str] = None,
                                  controls: List[Control] = None) -> Optional[ADComputer]:
        """ Find a Computer in AD based on a specified sAMAccountName name and return it along with any
        requested attributes.
        :param computer_name: The sAMAccountName name of the computer. Because a lot of people get a bit confused on
                              what a computer name, as many systems leave out the trailing $ that's common to many
                              computer sAMAccountNames when showing it, if computer_name does not end in a trailing $
                              and no computer can be found with computer_name, a lookup will be attempted for the
                              computer_name with a trailing $ added.
        :param attributes_to_lookup: A list of additional LDAP attributes to query for the computer. Regardless of
                                     what's specified, the computer's name and object class attributes will be queried.
        :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                         whether or not certain properties/attributes are critical, which influences whether a search
                         may succeed or fail based on their availability.
        :returns: an ADComputer object or None if the computer does not exist.
        """
        # build a compound filter for users with this samaccountname
        search_filter = '(&({sam_attr}={sam_name}){type_filter})'.format(
            sam_attr=ldap_constants.AD_ATTRIBUTE_SAMACCOUNT_NAME,
            sam_name=computer_name,
            type_filter=ldap_constants.FIND_COMPUTER_FILTER)
        res = self._find_ad_objects_and_attrs(self.domain_search_base, search_filter, SUBTREE,
                                              attributes_to_lookup, 1, ADUser, controls)
        if not res:
            if computer_name.endswith('$'):
                return None
            # if we didn't get a sAMAccountName ending in $, try a lookup for one ending in $
            alt_computer_name = computer_name + '$'
            logger.info('No computer results found for sAMAccountName %s - attempting lookup for sAMAccountName %s',
                        computer_name, alt_computer_name)
            search_filter = '(&({sam_attr}={sam_name}){type_filter})'.format(
                sam_attr=ldap_constants.AD_ATTRIBUTE_SAMACCOUNT_NAME,
                sam_name=alt_computer_name,
                type_filter=ldap_constants.FIND_COMPUTER_FILTER)
            res = self._find_ad_objects_and_attrs(self.domain_search_base, search_filter, SUBTREE,
                                                  attributes_to_lookup, 1, ADUser, controls)
            if not res:
                return None
        return res[0]

    def find_computer_by_sid(self, computer_sid: Union[security_constants.WellKnownSID, str, sd_utils.ObjectSid],
                             attributes_to_lookup: List[str] = None,
                             controls: List[Control] = None) -> Optional[ADComputer]:
        """ Find a Computer in AD given its SID.
        This function takes in a computer's objectSID and then looks up the computer in AD using it. SIDs are unique
        so only a single entry can be found at most.
        The computer SID can be in many formats (well known SID enum, ObjectSID object, canonical SID format,
        or bytes) and so all 4 possible formats are handled.
        :param computer_sid: The computer SID. This may either be a well-known SID enum, an ObjectSID object, a string
                             SID in canonical format (e.g. S-1-1-0), object SID bytes, or the hex representation of
                             such bytes.
        :param attributes_to_lookup: A list of additional LDAP attributes to query for the computer. Regardless of
                                     what's specified, the computer's name and object class attributes will be queried.
        :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                         whether or not certain properties/attributes are critical, which influences whether a search
                         may succeed or fail based on their availability.
        :returns: an ADComputer object or None if the computer does not exist.
        """
        return self.find_object_by_sid(computer_sid, attributes_to_lookup,
                                       object_class=ldap_constants.COMPUTER_OBJECT_CLASS, return_type=ADComputer,
                                       controls=controls)

    def find_computer_by_name(self, computer_name: str, attributes_to_lookup: List[str] = None,
                              controls: List[Control] = None) -> Optional[ADComputer]:
        """ Find a Computer in AD based on a provided name.
        This function takes in a generic name which can be either a distinguished name, a common name, or a
        sAMAccountName, and tries to find a unique computer identified by it and return information on the computer.
        :param computer_name: The name of the computer, which may be a DN, common name, or sAMAccountName.
        :param attributes_to_lookup: A list of additional LDAP attributes to query for the computer. Regardless of
                                     what's specified, the computer's name and object class attributes will be queried.
        :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                         whether or not certain properties/attributes are critical, which influences whether a search
                         may succeed or fail based on their availability.
        :returns: an ADComputer object or None if the computer does not exist.
        :raises: a DuplicateNameException if more than one entry exists with this name.
        """
        return self._find_by_name_common(computer_name, attributes_to_lookup, ADComputer, controls=controls)

    def find_users_by_attribute(self, attribute_name: str, attribute_value, attributes_to_lookup: List[str] = None,
                                size_limit: int = 0, controls: List[Control] = None) -> List[ADUser]:
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
        :returns: a list of ADUser objects representing users with the specified value for the specified attribute.
        """
        return self.find_objects_with_attribute(attribute_name, attribute_value, attributes_to_lookup, size_limit,
                                                ldap_constants.USER_OBJECT_CLASS, ADUser, controls)

    def find_users_by_common_name(self, user_name: str, attributes_to_lookup: List[str] = None,
                                  controls: List[Control] = None) -> List[ADUser]:
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

    def find_user_by_distinguished_name(self, user_dn: str, attributes_to_lookup: List[str] = None,
                                        controls: List[Control] = None) -> Optional[ADUser]:
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

    def find_user_by_sam_name(self, user_name: str, attributes_to_lookup: List[str] = None,
                              controls: List[Control] = None) -> Optional[ADUser]:
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
        search_filter = '(&({sam_attr}={sam_name}){type_filter})'.format(
            sam_attr=ldap_constants.AD_ATTRIBUTE_SAMACCOUNT_NAME,
            sam_name=user_name,
            type_filter=ldap_constants.FIND_USER_FILTER)
        res = self._find_ad_objects_and_attrs(self.domain_search_base, search_filter, SUBTREE,
                                              attributes_to_lookup, 1, ADUser, controls)
        if not res:
            return None
        return res[0]

    def find_user_by_sid(self, user_sid: Union[security_constants.WellKnownSID, str, sd_utils.ObjectSid],
                         attributes_to_lookup: List[str] = None, controls: List[Control] = None) -> Optional[ADUser]:
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
        :returns: an ADUser object or None if the user does not exist.
        """
        return self.find_object_by_sid(user_sid, attributes_to_lookup, object_class=ldap_constants.USER_OBJECT_CLASS,
                                       return_type=ADUser, controls=controls)

    def find_user_by_name(self, user_name: str, attributes_to_lookup: List[str] = None,
                          controls: List[Control] = None) -> Optional[ADUser]:
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
        return self._find_by_name_common(user_name, attributes_to_lookup, ADUser, controls=controls)

    def _find_by_name_common(self, name: str, attributes_to_lookup: List[str], lookup_type,
                             controls: List[Control] = None):
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
        if lookup_type is ADUser:
            dn_lookup_func = self.find_user_by_distinguished_name
            sam_lookup_func = self.find_user_by_sam_name
            cn_lookup_func = self.find_users_by_common_name
        elif lookup_type is ADComputer:
            dn_lookup_func = self.find_computer_by_distinguished_name
            sam_lookup_func = self.find_computer_by_sam_name
            cn_lookup_func = self.find_computers_by_common_name

        if is_dn:
            return dn_lookup_func(name, attributes_to_lookup, controls=controls)
        res = sam_lookup_func(name, attributes_to_lookup)
        if res:
            return res
        result_list = cn_lookup_func(name, attributes_to_lookup, controls=controls)
        if not result_list:
            return None
        if len(result_list) > 1:
            insert = 'object'
            if lookup_type is ADUser:
                insert = 'user'
            elif lookup_type is ADGroup:
                insert = 'group'
            elif lookup_type is ADComputer:
                insert = 'computer'
            raise DuplicateNameException('Multiple {}s found with name "{}". Please either repeat the search '
                                         'using a distinguished name or sAMAccountName, or adjust the session '
                                         'search base using set_domain_search_base to limit searches such that only '
                                         'one result is found. Alternatively you may perform a lookup by common name '
                                         'and select which {} entry you want to use from multiple.'
                                         .format(insert, name, insert))
        return result_list[0]

    def _figure_out_search_attributes_for_user_or_group(self, attributes_to_lookup: List[str]):
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

    def find_groups_for_entities(self, entities: List[Union[str, ADObject]], attributes_to_lookup: List[str] = None,
                                 lookup_by_name_fn: callable = None, controls: List[Control] = None,
                                 skip_validation: bool = False) -> Dict[Union[str, ADObject], List[ADGroup]]:
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
        :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                Defaults to False. This can be used to make this function more performant when
                                the caller knows all the distinguished names being specified are valid, as it
                                performs far fewer queries.
        :returns: A dictionary mapping input entities to lists of ADGroup object representing their parent groups.
        :raises: a DuplicateNameException if an entity name is specified and more than one entry exists with the name.
        :raises: InvalidLdapParameterException if any non-string non-ADObject types are found in entities, or if any
                 non-distinguished name strings are specified.
        """
        # make a map of entity distinguished names to entities passed in. we'll use this when constructing
        # our return dictionary as well
        entity_dns_to_entities = ldap_utils.normalize_entities_to_entity_dns(entities, lookup_by_name_fn, controls,
                                                                             skip_validation)

        filter_pieces = []
        for entity_dn in entity_dns_to_entities:
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
            for entity_dn in entity_dns_to_entities:
                if entity_dn in member_set:
                    # get our input entity for the result dict
                    entity = entity_dns_to_entities[entity_dn]
                    mapping_dict[entity].append(result)
        return mapping_dict

    def find_groups_for_group(self, group: Union[str, ADGroup], attributes_to_lookup: List[str] = None,
                              controls: List[Control] = None, skip_validation: bool = False) -> List[ADGroup]:
        """ Find the groups that a group belongs to, look up attributes of theirs, and return information about them.

        :param group: The group to lookup group memberships for. This can either be an ADGroup or a string name of an
                      AD group. If it is a string, the group will be looked up first to get unique distinguished name
                      information about it unless it is a distinguished name.
        :param attributes_to_lookup: A list of string LDAP attributes to look up in addition to our basic attributes.
        :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                         whether or not certain properties/attributes are critical, which influences whether a search
                         may succeed or fail based on their availability.
        :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                Defaults to False. This can be used to make this function more performant when
                                the caller knows all the distinguished names being specified are valid, as it
                                performs far fewer queries.
        :returns: A list of ADGroup objects representing the groups that this group belongs to.
        :raises: a DuplicateNameException if a group name is specified and more than one entry exists with the name.
        :raises: a InvalidLdapParameterException if the group name is not a string or ADGroup.
        """
        result_dict = self.find_groups_for_entities([group], attributes_to_lookup, self.find_group_by_name,
                                                    controls, skip_validation=skip_validation)
        return result_dict[group]

    def find_groups_for_groups(self, groups: List[Union[str, ADGroup]], attributes_to_lookup: List[str] = None,
                               controls: List[Control] = None,
                               skip_validation: bool = False) -> Dict[Union[str, ADGroup], List[ADGroup]]:
        """ Find the groups that a list of groups belong to, look up attributes of theirs, and return information about
        them.

        :param groups: The groups to lookup group memberships for. This can be a list of either ADGroup objects or
                       string names of AD groups. If they are strings, the groups will be looked up first to get unique
                       distinguished name information about them unless they are distinguished names.
        :param attributes_to_lookup: A list of string LDAP attributes to look up in addition to our basic attributes.
        :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                         whether or not certain properties/attributes are critical, which influences whether a search
                         may succeed or fail based on their availability.
        :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                Defaults to False. This can be used to make this function more performant when
                                the caller knows all the distinguished names being specified are valid, as it
                                performs far fewer queries.
        :returns: A dictionary mapping groups to lists of ADGroup objects representing the groups that they belong to.
        :raises: a DuplicateNameException if a group name is specified and more than one entry exists with the name.
        :raises: a InvalidLdapParameterException if any groups are not a string or ADGroup.
        """
        return self.find_groups_for_entities(groups, attributes_to_lookup, self.find_group_by_name, controls,
                                             skip_validation=skip_validation)

    def find_groups_for_user(self, user: Union[str, ADUser], attributes_to_lookup: List[str] = None,
                             controls: List[Control] = None, skip_validation: bool = False) -> List[ADGroup]:
        """ Find the groups that a user belongs to, look up attributes of theirs, and return information about them.

        :param user: The user to lookup group memberships for. This can either be an ADUser or a string name of an
                     AD user. If it is a string, the user will be looked up first to get unique distinguished name
                     information about it unless it is a distinguished name.
        :param attributes_to_lookup: A list of string LDAP attributes to look up in addition to our basic attributes.
        :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                         whether or not certain properties/attributes are critical, which influences whether a search
                         may succeed or fail based on their availability.
        :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                Defaults to False. This can be used to make this function more performant when
                                the caller knows all the distinguished names being specified are valid, as it
                                performs far fewer queries.
        :returns: A list of ADGroup objects representing the groups that this user belongs to.
        :raises: a DuplicateNameException if a user name is specified and more than one entry exists with the name.
        :raises: a InvalidLdapParameterException if the user name is not a string or ADUser.
        """
        result_dict = self.find_groups_for_entities([user], attributes_to_lookup, self.find_user_by_name, controls,
                                                    skip_validation=skip_validation)
        return result_dict[user]

    def find_groups_for_users(self, users: List[Union[str, ADUser]], attributes_to_lookup: List[str] = None,
                              controls: List[Control] = None,
                              skip_validation: bool = False) -> Dict[Union[str, ADUser], List[ADGroup]]:
        """ Find the groups that a list of users belong to, look up attributes of theirs, and return information about
        them.

        :param users: The users to lookup group memberships for. This can be a list of either ADUser objects or
                      string names of AD users. If they are strings, the users will be looked up first to get unique
                      distinguished name information about them unless they are distinguished names.
        :param attributes_to_lookup: A list of string LDAP attributes to look up in addition to our basic attributes.
        :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                         whether or not certain properties/attributes are critical, which influences whether a search
                         may succeed or fail based on their availability.
        :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                Defaults to False. This can be used to make this function more performant when
                                the caller knows all the distinguished names being specified are valid, as it
                                performs far fewer queries.
        :returns: A dictionary mapping users to lists of ADGroup objects representing the groups that they belong to.
        :raises: a DuplicateNameException if a user name is specified and more than one entry exists with the name.
        :raises: a InvalidLdapParameterException if any users are not a string or ADUser.
        """
        return self.find_groups_for_entities(users, attributes_to_lookup, self.find_user_by_name, controls,
                                             skip_validation=skip_validation)

    def find_groups_for_computer(self, computer: Union[str, ADComputer], attributes_to_lookup: List[str] = None,
                                 controls: List[Control] = None, skip_validation: bool = False) -> List[ADGroup]:
        """ Find the groups that a computer belongs to, look up attributes of theirs, and return information about them.

        :param computer: The computer to lookup group memberships for. This can either be an ADComputer or a string
                        name of an AD computer. If it is a string, the computer will be looked up first to get unique
                        distinguished name information about it unless it is a distinguished name.
        :param attributes_to_lookup: A list of string LDAP attributes to look up in addition to our basic attributes.
        :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                         whether or not certain properties/attributes are critical, which influences whether a search
                         may succeed or fail based on their availability.
        :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                Defaults to False. This can be used to make this function more performant when
                                the caller knows all the distinguished names being specified are valid, as it
                                performs far fewer queries.
        :returns: A list of ADGroup objects representing the groups that this user belongs to.
        :raises: a DuplicateNameException if a computer name is specified and more than one entry exists with the name.
        :raises: a InvalidLdapParameterException if the computer name is not a string or ADComputer.
        """
        result_dict = self.find_groups_for_entities([computer], attributes_to_lookup, self.find_computer_by_name,
                                                    controls, skip_validation=skip_validation)
        return result_dict[computer]

    def find_groups_for_computers(self, computers: List[Union[str, ADComputer]], attributes_to_lookup: List[str] = None,
                                  controls: List[Control] = None,
                                  skip_validation: bool = False) -> Dict[Union[str, ADComputer], List[ADGroup]]:
        """ Find the groups that a list of computers belong to, look up attributes of theirs, and return information
        about them.

        :param computers: The computers to lookup group memberships for. This can be a list of either ADComputer objects
                          or string names of AD computers. If they are strings, the computers will be looked up first
                          to get unique distinguished name information about them unless they are distinguished names.
        :param attributes_to_lookup: A list of string LDAP attributes to look up in addition to our basic attributes.
        :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                         whether or not certain properties/attributes are critical, which influences whether a search
                         may succeed or fail based on their availability.
        :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                Defaults to False. This can be used to make this function more performant when
                                the caller knows all the distinguished names being specified are valid, as it
                                performs far fewer queries.
        :returns: A dictionary mapping computers to lists of ADGroup objects representing the groups that they belong to
        :raises: a DuplicateNameException if a computer name is specified and more than one entry exists with the name.
        :raises: a InvalidLdapParameterException if any computers are not a string or ADComputer.
        """
        return self.find_groups_for_entities(computers, attributes_to_lookup, self.find_computer_by_name, controls,
                                             skip_validation=skip_validation)

    def find_members_of_group(self, group: Union[str, ADGroup], attributes_to_lookup: List[str] = None,
                              controls: List[Control] = None,
                              skip_validation: bool = False) -> List[Union[ADUser, ADGroup, ADComputer, ADObject]]:
        """ Find the members of a group in the domain, along with attributes of the members.

        :param group: Either a string name of a group or ADGroup to look up the members of.
        :param attributes_to_lookup: Attributes to look up about the members of each group.
        :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                         whether or not certain properties/attributes are critical, which influences whether a search
                         may succeed or fail based on their availability.
        :param skip_validation: If true, assume all members exist and do not raise an error if we fail to look one up.
                                Instead, a placeholder object will be used for members that could not be found.
                                Defaults to False.
        :return: A list of objects representing the group's members.
                 The objects may be of type ADUser, ADComputer, ADGroup, etc. - this function attempts to cast all
                 member objects to the most accurate object type representing them. ADObject will be used for members
                 that do not match any of the more specific object types in the library
                 (e.g. foreign security principals).
        :raises: InvalidLdapParameterException if the group is not a string or ADGroup
        :raises: ObjectNotFoundException if the group cannot be found.
        :raises: DomainSearchException if skip_validation is False and any group members cannot be found.
        """
        single_map = self.find_members_of_groups([group], attributes_to_lookup, controls,
                                                 skip_validation=skip_validation)
        return single_map[group]

    def find_members_of_groups(self, groups: List[Union[str, ADGroup]], attributes_to_lookup: List[str] = None,
                               controls: List[Control] = None,
                               skip_validation: bool = False) -> Dict[Union[str, ADGroup],
                                                                      List[Union[ADUser, ADGroup,
                                                                                 ADComputer, ADObject]]]:
        """ Find the members of one or more groups in the domain, along with attributes of the members.

        :param groups: A list of either strings or ADGroups to look up the members of.
        :param attributes_to_lookup: Attributes to look up about the members of each group.
        :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                         whether or not certain properties/attributes are critical, which influences whether a search
                         may succeed or fail based on their availability.
        :param skip_validation: If true, assume all members exist and do not raise an error if we fail to look one up.
                                Instead, a placeholder object will be used for members that could not be found.
                                Defaults to False.
        :return: A dictionary mapping groups from the input list to lists of objects representing their members.
                 The objects may be of type ADUser, ADComputer, ADGroup, etc. - this function attempts to cast all
                 member objects to the most accurate object type representing them. ADObject will be used for members
                 that do not match any of the more specific object types in the library
                 (e.g. foreign security principals).
        :raises: InvalidLdapParameterException if any groups are not strings or ADGroups
        :raises: ObjectNotFoundException if any groups cannot be found.
        :raises: DomainSearchException if skip_validation is False and any group members cannot be found.
        """
        all_member_dns_set = set()
        group_to_member_dn_map = {}
        for group in groups:
            if isinstance(group, ADGroup):
                # if our group is an ADGroup, we can do the lookup by DN which is most efficient
                informed_group_object = self.find_group_by_distinguished_name(group.distinguished_name,
                                                                              [ldap_constants.AD_ATTRIBUTE_MEMBER],
                                                                              controls=controls)
            elif isinstance(group, str):
                informed_group_object = self.find_group_by_name(group, [ldap_constants.AD_ATTRIBUTE_MEMBER],
                                                                controls=controls)
            else:
                raise InvalidLdapParameterException('All groups must be either strings or ADGroup objects. {} is not.'
                                                    .format(group))
            if informed_group_object is None:
                raise ObjectNotFoundException('No group could be found in the domain with the Group object class using '
                                              'group {}'.format(group))
            # add our members to our set and update our map
            member_dns = informed_group_object.get(ldap_constants.AD_ATTRIBUTE_MEMBER)
            all_member_dns_set.update(member_dns)
            group_to_member_dn_map[group] = member_dns

        logger.debug('Found %s unique members across %s groups', len(all_member_dns_set), len(groups))
        # now we need to look up all of the members.
        member_dn_to_objects = {}
        for member_dn in all_member_dns_set:
            ad_obj = self.find_object_by_distinguished_name(member_dn, attributes_to_lookup, controls=controls)
            if ad_obj is None:
                if skip_validation:
                    # use a placeholder object with just the dn
                    ad_obj = ADObject(member_dn, {}, self.domain)
                else:
                    raise DomainSearchException('An object with distinguished name {} was listed as a member of a '
                                                'group but information about it could not be found when searching the '
                                                'domain. This may indicate that the object was deleted in parallel '
                                                'with this search being performed, or an issue with the permissions '
                                                'of this session. If you believe it was a race with the domain '
                                                'changing, please retry this operation. Otherwise, please examine the '
                                                'permissions of the session.'.format(member_dn))
            member_dn_to_objects[member_dn] = ad_obj

        group_to_members_map = {}
        for group in groups:
            group_member_dns = group_to_member_dn_map[group]
            group_to_members_map[group] = []
            for dn in group_member_dns:
                member_obj = member_dn_to_objects[dn]
                group_to_members_map[group].append(member_obj)
        return group_to_members_map

    def find_members_of_group_recursive(self, group: Union[str, ADGroup], attributes_to_lookup: List[str] = None,
                                        controls: List[Control] = None, skip_validation: bool = False,
                                        maximum_nesting_depth: int = None,
                                        flatten: bool = False) -> List[Dict[Union[str, ADGroup], List[ADGroup]]]:
        """ Find the members of a group in the domain, along with attributes of the members.

        :param group: Either a string name of a group or ADGroup to look up the members of.
        :param attributes_to_lookup: Attributes to look up about the members of each group.
        :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                         whether or not certain properties/attributes are critical, which influences whether a search
                         may succeed or fail based on their availability.
        :param skip_validation: If true, assume all members exist and do not raise an error if we fail to look one up.
                                Instead, a placeholder object will be used for members that could not be found.
                                Defaults to False.
        :param maximum_nesting_depth: A limit to the number of levels of nesting to recurse beyond the first lookup.
                                      A level of 0 makes this behave the same as find_members_of_groups and a level of
                                      None means recurse until we've gone through all nesting. Defaults to None.
        :param flatten: If set to True, a 1-item list of a single dictionary mapping the input group to a list of
                        all members found recursively will be returned. This discards information about whether
                        a member is a direct member or is a member via nesting, and what those relationships are.
                        As an example, instead of returning [{group1 -> [group2, user1]}, {group2 -> [user2, user3]}],
                        we would return [{group1 -> [group2, user1, user2, user3]}]. This makes iterating members
                        simpler, but removes the ability to use information about the descendants of nested groups
                        as independent groups later on.
                        Defaults to False.
        :return: A list of dictionaries mapping groups to objects representing the group's members.
                 The first dictionary maps the input group to its members; the second dictionary maps the groups that
                 were members of the groups in the first dictionary to their members, and so on and so forth.
                 The objects may be of type ADUser, ADComputer, ADGroup, etc. - this function attempts to cast all
                 member objects to the most accurate object type representing them. ADObject will be used for members
                 that do not match any of the more specific object types in the library
                 (e.g. foreign security principals).
        :raises: InvalidLdapParameterException if the group is not a string or ADGroup
        :raises: ObjectNotFoundException if the group cannot be found.
        :raises: DomainSearchException if skip_validation is False and any group members cannot be found.
        """
        maps = self.find_members_of_groups_recursive([group], attributes_to_lookup, controls=controls,
                                                     skip_validation=skip_validation,
                                                     maximum_nesting_depth=maximum_nesting_depth)
        if not flatten or len(maps) == 1:
            return maps
        # start with a set of the direct members of our group
        all_unique_members = set(maps[0][group])
        logger.debug('Beginning flattening with %s direct members of group', len(all_unique_members))
        for index, groups_to_members_map in enumerate(maps[1:]):
            logger.debug('Flattening the members of %s groups nested %s level deep', len(groups_to_members_map), index)
            all_member_lists = groups_to_members_map.values()
            for member_list in all_member_lists:
                all_unique_members.update(member_list)
        logger.debug('%s unique members found after flattening', len(all_unique_members))
        return [{group: list(all_unique_members)}]

    def find_members_of_groups_recursive(self, groups: List[Union[str, ADGroup]], attributes_to_lookup: List[str] = None,
                                         controls: List[Control] = None, skip_validation: bool = False,
                                         maximum_nesting_depth: int = None) -> List[Dict[Union[str, ADGroup],
                                                                                         List[ADGroup]]]:
        """ Find the members of a group in the domain, along with attributes of the members.

        :param groups: Either a string name of a group or ADGroup to look up the members of.
        :param attributes_to_lookup: Attributes to look up about the members of each group.
        :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                         whether or not certain properties/attributes are critical, which influences whether a search
                         may succeed or fail based on their availability.
        :param skip_validation: If true, assume all members exist and do not raise an error if we fail to look one up.
                                Instead, a placeholder object will be used for members that could not be found.
                                Defaults to False.
        :param maximum_nesting_depth: A limit to the number of levels of nesting to recurse beyond the first lookup.
                                      A level of 0 makes this behave the same as find_members_of_groups and a level of
                                      None means recurse until we've gone through all nesting. Defaults to None.
        :return: A list of dictionaries mapping groups to objects representing the group's members.
                 The first dictionary maps the input groups to members; the second dictionary maps the groups that
                 were members of the groups in the first dictionary to their members, and so on and so forth.
                 The objects may be of type ADUser, ADComputer, ADGroup, etc. - this function attempts to cast all
                 member objects to the most accurate object type representing them. ADObject will be used for members
                 that do not match any of the more specific object types in the library
                 (e.g. foreign security principals).
        :raises: InvalidLdapParameterException if the group is not a string or ADGroup
        :raises: ObjectNotFoundException if the group cannot be found.
        :raises: DomainSearchException if skip_validation is False and any group members cannot be found.
        """
        groups_to_members_maps = []
        depth = 0
        next_level_of_groups_to_lookup = groups
        # keep going while we have groups to lookup and haven't hit our max depth
        while next_level_of_groups_to_lookup and (maximum_nesting_depth is None or maximum_nesting_depth >= depth):
            groups_to_members_map = self.find_members_of_groups(next_level_of_groups_to_lookup, attributes_to_lookup,
                                                                controls=controls, skip_validation=skip_validation)
            groups_to_members_maps.append(groups_to_members_map)
            all_members_that_are_groups = set()
            for member_list in groups_to_members_map.values():
                members_that_are_groups = {member for member in member_list if isinstance(member, ADGroup)}
                all_members_that_are_groups.update(members_that_are_groups)

            next_level_of_groups_to_lookup = list(all_members_that_are_groups)
            depth += 1
        # if we ran out of nesting before we hit our depth, append empty dicts as needed
        while maximum_nesting_depth is not None and len(groups_to_members_maps) < maximum_nesting_depth + 1:
            groups_to_members_maps.append({})
        return groups_to_members_maps

    # FUNCTIONS FOR MODIFYING MEMBERSHIPS

    def _something_members_to_or_from_groups(self, members: List[Union[str, ADObject]],
                                             groups_to_modify: List[Union[str, ADGroup]],
                                             member_lookup_fn: callable, stop_and_rollback_on_error: bool,
                                             adding: bool, controls: List[Control],
                                             skip_validation: bool) -> List[Union[str, ADGroup]]:
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
                                                                            controls, skip_validation)
        member_dn_list = list(normalized_member_dns.keys())
        normalized_target_group_dns = ldap_utils.normalize_entities_to_entity_dns(groups_to_modify,
                                                                                  self.find_group_by_name,
                                                                                  controls, skip_validation)
        target_group_list = list(normalized_target_group_dns.keys())

        overlap = set(target_group_list).intersection(set(member_dn_list))
        if overlap:
            # this can only happen for groups
            verb = 'added to' if adding else 'removed from'
            raise MembershipModificationException('Groups may not be {} themselves. The following group(s) '
                                                  'appeared in both the list of members to add and the list of '
                                                  'groups to add them to: {}'.format(verb, ', '.join(overlap)))

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
                                                                  # we already validated and don't need to redo it
                                                                  # on rollback
                                                                  controls=controls, skip_validation=True)
                    except MembershipModificationException:
                        logger.error('Failed to completely rollback changes after failure. '
                                     'Halting and raising exception')
                        raise MembershipModificationRollbackException(
                            'Failed to modify group with distinguished name {} and rollback of '
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

    def add_groups_to_groups(self, groups_to_add: List[Union[str, ADGroup]],
                             groups_to_add_them_to: List[Union[str, ADGroup]],
                             stop_and_rollback_on_error: bool = True, controls: List[Control] = None,
                             skip_validation: bool = False) -> List[Union[str, ADGroup]]:
        """ Add one or more groups to one or more other groups as members. This function attempts to be idempotent
        and will not re-add groups that are already members.

        :param groups_to_add: A list of groups to add to other groups. These may either be ADGroup objects or string
                              name identifiers for groups.
        :param groups_to_add_them_to: A list of groups to add members to. These may either be ADGroup objects or string
                                      name identifiers for groups.
        :param stop_and_rollback_on_error: If true, failure to add any of the groups to any of the other groups will
                                           cause us to try and remove any groups that have been added from any of the
                                           groups that we successfully added members to.
        :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                         whether or not certain properties/attributes are critical, which influences whether a search
                         may succeed or fail based on their availability.
        :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                Defaults to False. This can be used to make this function more performant when
                                the caller knows all the distinguished names being specified are valid, as it
                                performs far fewer queries.
        :returns: A list of groups that successfully had members added. This will always be all the groups unless
                  stop_and_rollback_on_error is False.
        :raises: MembershipModificationException if any groups being added also exist in the groups to add them to, or
                 if we fail to add groups to any other groups and rollback succeeds.
        :raises: MembershipModificationRollbackException if we fail to add any groups to other groups, and then also
                 fail when removing the groups that had been added successfully, leaving us in a partially completed
                 state. This may occur if the session has permission to add members but not to remove members.
        """
        return self._something_members_to_or_from_groups(groups_to_add, groups_to_add_them_to, self.find_group_by_name,
                                                         stop_and_rollback_on_error, adding=True, controls=controls,
                                                         skip_validation=skip_validation)

    def add_users_to_groups(self, users_to_add: List[Union[str, ADUser]],
                            groups_to_add_them_to: List[Union[str, ADGroup]],
                            stop_and_rollback_on_error: bool = True, controls: List[Control] = None,
                            skip_validation: bool = False) -> List[Union[str, ADGroup]]:
        """ Add one or more users to one or more groups as members. This function attempts to be idempotent
        and will not re-add users that are already members.

        :param users_to_add: A list of users to add to other groups. These may either be ADUser objects or string
                             name identifiers for users.
        :param groups_to_add_them_to: A list of groups to add members to. These may either be ADGroup objects or string
                                      name identifiers for groups.
        :param stop_and_rollback_on_error: If true, failure to add any of the users to any of the groups will
                                           cause us to try and remove any users that have been added from any of the
                                           groups that we successfully added members to.
        :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                         whether or not certain properties/attributes are critical, which influences whether a search
                         may succeed or fail based on their availability.
        :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                Defaults to False. This can be used to make this function more performant when
                                the caller knows all the distinguished names being specified are valid, as it
                                performs far fewer queries.
        :returns: A list of groups that successfully had members added. This will always be all the groups unless
                  stop_and_rollback_on_error is False.
        :raises: MembershipModificationException if we fail to add groups to any other groups and rollback succeeds.
        :raises: MembershipModificationRollbackException if we fail to add any groups to other groups, and then also
                 fail when removing the groups that had been added successfully, leaving us in a partially completed
                 state. This may occur if the session has permission to add members but not to remove members.
        """
        return self._something_members_to_or_from_groups(users_to_add, groups_to_add_them_to, self.find_user_by_name,
                                                         stop_and_rollback_on_error, adding=True, controls=controls,
                                                         skip_validation=skip_validation)

    def add_computers_to_groups(self, computers_to_add: List[Union[str, ADComputer]],
                                groups_to_add_them_to: List[Union[str, ADGroup]],
                                stop_and_rollback_on_error: bool = True, controls: List[Control] = None,
                                skip_validation: bool = False) -> List[Union[str, ADGroup]]:
        """ Add one or more computers to one or more groups as members. This function attempts to be idempotent
        and will not re-add computers that are already members.

        :param computers_to_add: A list of computers to add to other groups. These may either be ADComputer objects or
                                 string name identifiers for computers.
        :param groups_to_add_them_to: A list of groups to add members to. These may either be ADGroup objects or string
                                      name identifiers for groups.
        :param stop_and_rollback_on_error: If true, failure to add any of the computers to any of the groups will
                                           cause us to try and remove any computers that have been added from any of the
                                           groups that we successfully added members to.
        :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                         whether or not certain properties/attributes are critical, which influences whether a search
                         may succeed or fail based on their availability.
        :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                Defaults to False. This can be used to make this function more performant when
                                the caller knows all the distinguished names being specified are valid, as it
                                performs far fewer queries.
        :returns: A list of groups that successfully had members added. This will always be all the groups unless
                  stop_and_rollback_on_error is False.
        :raises: MembershipModificationException if we fail to add groups to any other groups and rollback succeeds.
        :raises: MembershipModificationRollbackException if we fail to add any groups to other groups, and then also
                 fail when removing the groups that had been added successfully, leaving us in a partially completed
                 state. This may occur if the session has permission to add members but not to remove members.
        """
        return self._something_members_to_or_from_groups(computers_to_add, groups_to_add_them_to,
                                                         self.find_computer_by_name, stop_and_rollback_on_error,
                                                         adding=True, controls=controls,
                                                         skip_validation=skip_validation)

    def remove_groups_from_groups(self, groups_to_remove: List[Union[str, ADGroup]],
                                  groups_to_remove_them_from: List[Union[str, ADGroup]],
                                  stop_and_rollback_on_error: bool = True, controls: List[Control] = None,
                                  skip_validation: bool = False) -> List[Union[str, ADGroup]]:
        """ Remove one or more groups from one or more groups as members. This function attempts to be idempotent
        and will not remove groups that are not already members.

        :param groups_to_remove: A list of groups to remove from other groups. These may either be ADGroup objects or
                                 string name identifiers for groups.
        :param groups_to_remove_them_from: A list of groups to remove members from. These may either be ADGroup objects
                                           or string name identifiers for groups.
        :param stop_and_rollback_on_error: If true, failure to remove any of the groups from any of the other groups
                                           will cause us to try and add any groups that have been removed back to any
                                           of the groups that we successfully removed members from.
        :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                         whether or not certain properties/attributes are critical, which influences whether a search
                         may succeed or fail based on their availability.
        :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                Defaults to False. This can be used to make this function more performant when
                                the caller knows all the distinguished names being specified are valid, as it
                                performs far fewer queries.
        :returns: A list of groups that successfully had members removed. This will always be all the groups unless
                  stop_and_rollback_on_error is False.
        :raises: MembershipModificationException if we fail to remove groups from any other groups and rollback succeeds
        :raises: MembershipModificationRollbackException if we fail to remove any groups from other groups, and then
                 also fail when adding the groups that had been removed successfully, leaving us in a partially
                 completed state. This may occur if the session has permission to remove members but not to add members.
        """
        return self._something_members_to_or_from_groups(groups_to_remove, groups_to_remove_them_from,
                                                         self.find_group_by_name, stop_and_rollback_on_error,
                                                         adding=False, controls=controls,
                                                         skip_validation=skip_validation)

    def remove_users_from_groups(self, users_to_remove: List[Union[str, ADUser]],
                                 groups_to_remove_them_from: List[Union[str, ADGroup]],
                                 stop_and_rollback_on_error: bool = True, controls: List[Control] = None,
                                 skip_validation: bool = False) -> List[Union[str, ADGroup]]:
        """ Remove one or more users from one or more groups as members. This function attempts to be idempotent
        and will not remove users that are not already members.

        :param users_to_remove: A list of users to remove from groups. These may either be ADUsers objects or
                                string name identifiers for users.
        :param groups_to_remove_them_from: A list of groups to remove members from. These may either be ADGroup objects
                                           or string name identifiers for groups.
        :param stop_and_rollback_on_error: If true, failure to remove any of the users from any of the groups
                                           will cause us to try and add any users that have been removed back to any
                                           of the groups that we successfully removed members from.
        :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                         whether or not certain properties/attributes are critical, which influences whether a search
                         may succeed or fail based on their availability.
        :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                Defaults to False. This can be used to make this function more performant when
                                the caller knows all the distinguished names being specified are valid, as it
                                performs far fewer queries.
        :returns: A list of groups that successfully had members removed. This will always be all the groups unless
                  stop_and_rollback_on_error is False.
        :raises: MembershipModificationException if we fail to remove users from any groups and rollback succeeds
        :raises: MembershipModificationRollbackException if we fail to remove any users from groups, and then
                 also fail when adding the users that had been removed successfully, leaving us in a partially
                 completed state. This may occur if the session has permission to remove members but not to add members.
        """
        return self._something_members_to_or_from_groups(users_to_remove, groups_to_remove_them_from,
                                                         self.find_user_by_name, stop_and_rollback_on_error,
                                                         adding=False, controls=controls,
                                                         skip_validation=skip_validation)

    def remove_computers_from_groups(self, computers_to_remove: List[Union[str, ADComputer]],
                                     groups_to_remove_them_from: List[Union[str, ADGroup]],
                                     stop_and_rollback_on_error: bool = True, controls: List[Control] = None,
                                     skip_validation: bool = False) -> List[Union[str, ADGroup]]:
        """ Remove one or more computers from one or more groups as members. This function attempts to be idempotent
        and will not remove computers that are not already members.

        :param computers_to_remove: A list of computers to remove from groups. These may either be ADComputer objects or
                                    string name identifiers for computers.
        :param groups_to_remove_them_from: A list of groups to remove members from. These may either be ADGroup objects
                                           or string name identifiers for groups.
        :param stop_and_rollback_on_error: If true, failure to remove any of the computers from any of the groups
                                           will cause us to try and add any computers that have been removed back to any
                                           of the groups that we successfully removed members from.
        :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                         whether or not certain properties/attributes are critical, which influences whether a search
                         may succeed or fail based on their availability.
        :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                Defaults to False. This can be used to make this function more performant when
                                the caller knows all the distinguished names being specified are valid, as it
                                performs far fewer queries.
        :returns: A list of groups that successfully had members removed. This will always be all the groups unless
                  stop_and_rollback_on_error is False.
        :raises: MembershipModificationException if we fail to remove computers from any groups and rollback succeeds
        :raises: MembershipModificationRollbackException if we fail to remove any computers from groups, and then
                 also fail when adding the computers that had been removed successfully, leaving us in a partially
                 completed state. This may occur if the session has permission to remove members but not to add members.
        """
        return self._something_members_to_or_from_groups(computers_to_remove, groups_to_remove_them_from,
                                                         self.find_computer_by_name, stop_and_rollback_on_error,
                                                         adding=False, controls=controls,
                                                         skip_validation=skip_validation)

    # Functions for managing permissions within the domain

    def find_security_descriptor_for_group(self, group: Union[str, ADGroup], include_sacl: bool = False,
                                           skip_validation: bool = False) -> sd_utils.SelfRelativeSecurityDescriptor:
        """ Given a group, find its security descriptor. The security descriptor will be returned as a
        SelfRelativeSecurityDescriptor object.

        :param group: The group for which we will read the security descriptor. This may be an ADGroup object or a
                      string name identifying the group (in which case it will be looked up).
        :param include_sacl: If true, we will attempt to read the System ACL for the group in addition to the
                             Discretionary ACL and owner information when reading the security descriptor. This is
                             more privileged than just getting the Discretionary ACL and owner information.
                             Defaults to False.
        :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                Defaults to False. This can be used to make this function more performant when
                                the caller knows all the distinguished names being specified are valid, as it
                                performs far fewer queries.
        :raises: ObjectNotFoundException if the group cannot be found.
        :raises: InvalidLdapParameterException if the group specified is not a string or an ADGroup object
        :raises: SecurityDescriptorDecodeException if we fail to decode the security descriptor.
        """
        group = self._validate_group_and_get_group_obj(group, skip_validation=skip_validation)
        return self.find_security_descriptor_for_object(group, include_sacl=include_sacl,
                                                        skip_validation=skip_validation)

    def find_security_descriptor_for_user(self, user: Union[str, ADUser], include_sacl: bool = False,
                                          skip_validation: bool = False) -> sd_utils.SelfRelativeSecurityDescriptor:
        """ Given a user, find its security descriptor. The security descriptor will be returned as a
        SelfRelativeSecurityDescriptor object.

        :param user: The user for which we will read the security descriptor. This may be an ADUser object or a
                     string name identifying the user (in which case it will be looked up).
        :param include_sacl: If true, we will attempt to read the System ACL for the user in addition to the
                             Discretionary ACL and owner information when reading the security descriptor. This is
                             more privileged than just getting the Discretionary ACL and owner information.
                             Defaults to False.
        :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                Defaults to False. This can be used to make this function more performant when
                                the caller knows all the distinguished names being specified are valid, as it
                                performs far fewer queries.
        :raises: ObjectNotFoundException if the user cannot be found.
        :raises: InvalidLdapParameterException if the user specified is not a string or an ADUser object
        :raises: SecurityDescriptorDecodeException if we fail to decode the security descriptor.
        """
        user = self._validate_user_and_get_user_obj(user, skip_validation=skip_validation)
        return self.find_security_descriptor_for_object(user, include_sacl=include_sacl,
                                                        skip_validation=skip_validation)

    def find_security_descriptor_for_computer(self, computer: Union[str, ADComputer], include_sacl: bool = False,
                                              skip_validation: bool = False) -> sd_utils.SelfRelativeSecurityDescriptor:
        """ Given a computer, find its security descriptor. The security descriptor will be returned as a
        SelfRelativeSecurityDescriptor object.

        :param computer: The computer for which we will read the security descriptor. This may be an ADComputer object
                         or a string name identifying the computer (in which case it will be looked up).
        :param include_sacl: If true, we will attempt to read the System ACL for the user in addition to the
                             Discretionary ACL and owner information when reading the security descriptor. This is
                             more privileged than just getting the Discretionary ACL and owner information.
                             Defaults to False.
        :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                Defaults to False. This can be used to make this function more performant when
                                the caller knows all the distinguished names being specified are valid, as it
                                performs far fewer queries.
        :raises: ObjectNotFoundException if the computer cannot be found.
        :raises: InvalidLdapParameterException if the computer specified is not a string or an ADComputer object
        :raises: SecurityDescriptorDecodeException if we fail to decode the security descriptor.
        """
        computer = self._validate_computer_and_get_computer_obj(computer, skip_validation=skip_validation)
        return self.find_security_descriptor_for_object(computer, include_sacl=include_sacl,
                                                        skip_validation=skip_validation)

    def find_security_descriptor_for_object(self, ad_object: Union[str, ADObject], include_sacl: bool = False,
                                            skip_validation: bool = False) -> sd_utils.SelfRelativeSecurityDescriptor:
        """ Given an object, find its security descriptor. The security descriptor will be returned as a
        SelfRelativeSecurityDescriptor object.

        :param ad_object: The object for which we will read the security descriptor. This may be an ADObject object or a
                          string distinguished identifying the object.
        :param include_sacl: If true, we will attempt to read the System ACL for the object in addition to the
                             Discretionary ACL and owner information when reading the security descriptor. This is
                             more privileged than just getting the Discretionary ACL and owner information.
                             Defaults to False.
        :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                Defaults to False. This can be used to make this function more performant when
                                the caller knows all the distinguished names being specified are valid, as it
                                performs far fewer queries.
        :raises: ObjectNotFoundException if the object cannot be found.
        :raises: InvalidLdapParameterException if the ad_object specified is not a string DN or an ADObject object
        :raises: SecurityDescriptorDecodeException if we fail to decode the security descriptor.
        """
        ad_object = self._validate_obj_and_get_ad_obj(ad_object, skip_validation=skip_validation)
        dn_to_search = ad_object.distinguished_name

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

    def set_object_security_descriptor(self, ad_object: Union[str, ADObject],
                                       new_sec_descriptor: sd_utils.SelfRelativeSecurityDescriptor,
                                       raise_exception_on_failure: bool = True,
                                       skip_validation: bool = False) -> bool:
        """ Set the security descriptor on an Active Directory object. This can be used to change the owner of an
        object in AD, change its permission ACEs, etc.

        :param ad_object: Either an ADObject object or string distinguished name referencing the object to be modified
        :param new_sec_descriptor: The security descriptor to set on the object.
        :param raise_exception_on_failure: If true, raise an exception when modifying the object fails instead of
                                           returning False.
        :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                Defaults to False. This can be used to make this function more performant when
                                the caller knows all the distinguished names being specified are valid, as it
                                performs far fewer queries.
        :returns: A boolean indicating success.
        :raises: ObjectNotFoundException if a string DN is specified and it cannot be found
        :raises: PermissionDeniedException if we fail to modify the Security Descriptor and raise_exception_on_failure
                 is true
        """
        ad_object = self._validate_obj_and_get_ad_obj(ad_object, skip_validation=skip_validation)
        dn_to_modify = ad_object.distinguished_name

        new_sec_descriptor_bytes = new_sec_descriptor.get_data(force_recompute=True)
        changes = {
            ldap_constants.AD_ATTRIBUTE_SECURITY_DESCRIPTOR: (MODIFY_REPLACE, [new_sec_descriptor_bytes])
        }
        res = self.ldap_connection.modify(dn_to_modify, changes)
        success, result, _, _ = ldap_utils.process_ldap3_conn_return_value(self.ldap_connection, res)
        logger.debug('Result of modifying security descriptor for %s: %s', dn_to_modify, result)

        if raise_exception_on_failure and not success:
            raise PermissionDeniedException('Failed to modify the security descriptor for object with distinguished '
                                            'name {} - this may be due to permission issues or an incomplete security '
                                            'descriptor. Result: {}'.format(dn_to_modify, result))
        return success

    def set_group_security_descriptor(self, group: Union[str, ADGroup],
                                      new_sec_descriptor: sd_utils.SelfRelativeSecurityDescriptor,
                                      raise_exception_on_failure: bool = True, skip_validation: bool = False) -> bool:
        """ Set the security descriptor on an Active Directory group. This can be used to change the owner of an
        group in AD, change its permission ACEs, etc.

        :param group: Either an ADGroup object or string name referencing the group to be modified
        :param new_sec_descriptor: The security descriptor to set on the object.
        :param raise_exception_on_failure: If true, raise an exception when modifying the object fails instead of
                                           returning False.
        :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                Defaults to False. This can be used to make this function more performant when
                                the caller knows all the distinguished names being specified are valid, as it
                                performs far fewer queries.
        :returns: A boolean indicating success.
        :raises: ObjectNotFoundException if a string DN is specified and it cannot be found
        :raises: PermissionDeniedException if we fail to modify the Security Descriptor and raise_exception_on_failure
                 is true
        """
        group = self._validate_group_and_get_group_obj(group, skip_validation=skip_validation)
        return self.set_object_security_descriptor(group, new_sec_descriptor,
                                                   raise_exception_on_failure=raise_exception_on_failure,
                                                   skip_validation=skip_validation)

    def set_user_security_descriptor(self, user: Union[str, ADUser],
                                     new_sec_descriptor: sd_utils.SelfRelativeSecurityDescriptor,
                                     raise_exception_on_failure: bool = True, skip_validation: bool = False) -> bool:
        """ Set the security descriptor on an Active Directory object. This can be used to change the owner of an
        user in AD, change its permission ACEs, etc.

        :param user: Either an ADUser object or string name referencing the user to be modified.
        :param new_sec_descriptor: The security descriptor to set on the object.
        :param raise_exception_on_failure: If true, raise an exception when modifying the object fails instead of
                                           returning False.
        :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                Defaults to False. This can be used to make this function more performant when
                                the caller knows all the distinguished names being specified are valid, as it
                                performs far fewer queries.
        :returns: A boolean indicating success.
        :raises: InvalidLdapParameterException if user is not a string or ADUser object
        :raises: ObjectNotFoundException if a string DN is specified and it cannot be found
        :raises: PermissionDeniedException if we fail to modify the Security Descriptor and raise_exception_on_failure
                 is true
        """
        user = self._validate_user_and_get_user_obj(user, skip_validation=skip_validation)
        return self.set_object_security_descriptor(user, new_sec_descriptor,
                                                   raise_exception_on_failure=raise_exception_on_failure,
                                                   skip_validation=skip_validation)

    def set_computer_security_descriptor(self, computer: Union[str, ADComputer],
                                         new_sec_descriptor: sd_utils.SelfRelativeSecurityDescriptor,
                                         raise_exception_on_failure: bool = True,
                                         skip_validation: bool = False) -> bool:
        """ Set the security descriptor on an Active Directory computer. This can be used to change the owner of a
        computer in AD, change its permission ACEs, etc.

        :param computer: Either an ADComputer object or string name referencing the computer to be modified.
        :param new_sec_descriptor: The security descriptor to set on the object.
        :param raise_exception_on_failure: If true, raise an exception when modifying the object fails instead of
                                           returning False.
        :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                Defaults to False. This can be used to make this function more performant when
                                the caller knows all the distinguished names being specified are valid, as it
                                performs far fewer queries.
        :returns: A boolean indicating success.
        :raises: InvalidLdapParameterException if computer is not a string or ADComputer object
        :raises: ObjectNotFoundException if a string DN is specified and it cannot be found
        :raises: PermissionDeniedException if we fail to modify the Security Descriptor and raise_exception_on_failure
                 is true
        """
        computer = self._validate_computer_and_get_computer_obj(computer, skip_validation=skip_validation)
        return self.set_object_security_descriptor(computer, new_sec_descriptor,
                                                   raise_exception_on_failure=raise_exception_on_failure,
                                                   skip_validation=skip_validation)

    def add_permission_to_object_security_descriptor(self, ad_object_to_modify: Union[str, ADObject],
                                                     sids_to_grant_permissions_to: List[Union[
                                                         str, sd_utils.ObjectSid, security_constants.WellKnownSID]],
                                                     access_masks_to_add: List[sd_utils.AccessMask] = None,
                                                     rights_guids_to_add: List[Union[ADRightsGuid, str]] = None,
                                                     read_property_guids_to_add: List[str] = None,
                                                     write_property_guids_to_add: List[str] = None,
                                                     raise_exception_on_failure: bool = True,
                                                     skip_validation: bool = False) -> bool:
        """ Add specified permissions to the security descriptor on an object for specified SIDs.
        This can be used to grant 1 or more other users/groups/computers/etc. the right to take broad actions or narrow
        privileged actions on the object, via adding access masks or rights guids respectively. It can also give
        1 or more users/groups/computers/etc. the ability to read or write specific properties on the object by
        specifying read or write property guids to add.

        This can, as an example, take a container object and give a user the right to delete it. Or take a group object
        and give a list of computers the right to read and write the group's members. Or take a computer and let a user
        reset its password without needing the current one. Etc. Etc.

        :param ad_object_to_modify: An ADObject or String distinguished name, referring to the object that will have
                                    the permissions on it modified.
        :param sids_to_grant_permissions_to: SIDs referring to the other entities that will be given new permissions
                                             on the object. These may be ObjectSID objects, SID strings, or
                                             WellKnownSIDs.
        :param access_masks_to_add: A list of AccessMask objects to grant to the SIDs. These represent broad categories
                                    of actions, such as GENERIC_READ and GENERIC_WRITE.
        :param rights_guids_to_add: A list of rights guids to grant to the SIDs. These may be specified as strings or
                                    as ADRightsGuid enums, and represent narrower permissions to grant to the SIDs for
                                    targeted actions such as Unexpire_Password or Apply_Group_Policy. Some of these
                                    do not make logical sense to use in all contexts, as some rights guids only have
                                    meaning in a self-relative context, or only have meaning on some object types.
                                    It is left up to the caller to decide what is meaningful.
        :param read_property_guids_to_add: A list of property guids that represent properties of the object that the
                                           SIDs will be granted the right to read. These must be strings.
        :param write_property_guids_to_add: A list of property guids that represent properties of the object that the
                                            SIDs will be granted the right to write. These must be strings.
        :param raise_exception_on_failure: A boolean indicating if an exception should be raised if we fail to update
                                           the security descriptor, instead of returning False. defaults to True
        :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                Defaults to False. This can be used to make this function more performant when
                                the caller knows all the distinguished names being specified are valid, as it
                                performs far fewer queries.
        :returns: A boolean indicating if we succeeded in updating the security descriptor.
        :raises: InvalidLdapParameterException if any inputs are the wrong type.
        :raises: ObjectNotFoundException if the a string distinguished name is specified and cannot be found.
        :raises: PermissionDeniedException if we fail to modify the Security Descriptor and raise_exception_on_failure
                 is true
        """
        # turn all of our SIDs into strings
        sid_strings = []
        for sid in sids_to_grant_permissions_to:
            if isinstance(sid, str):
                sid_strings.append(sid)
            elif isinstance(sid, security_constants.WellKnownSID):
                sid_strings.append(sid.value)
            elif isinstance(sid, sd_utils.ObjectSid):
                sid_strings.append(sid.to_canonical_string_format())
            else:
                raise InvalidLdapParameterException('All specified SIDs must be strings, ObjectSID objects, or'
                                                    'instances of the WellKnownSID enum. {} is not.'.format(sid))

        priv_guid_strings = []
        for priv_guid in rights_guids_to_add:
            if isinstance(priv_guid, str):
                priv_guid_strings.append(priv_guid)
            elif isinstance(priv_guid, ADRightsGuid):
                priv_guid_strings.append(priv_guid.value)
            else:
                raise InvalidLdapParameterException('All specified rights guids must be strings or instances of the'
                                                    'ADRightsGuid enum. {} is not.'.format(priv_guid))

        # make sure we have an AD object early, so that our next calls for the lookup for the current SD and for setting
        # the SD are more efficient
        ad_object_to_modify = self._validate_obj_and_get_ad_obj(ad_object_to_modify, skip_validation=skip_validation)
        current_sd = self.find_security_descriptor_for_object(ad_object_to_modify, skip_validation=skip_validation)

        for sid_string in sid_strings:
            current_sd = sd_utils.add_permissions_to_security_descriptor(current_sd, sid_string,
                                                                         access_masks=access_masks_to_add,
                                                                         privilege_guids=priv_guid_strings,
                                                                         read_property_guids=read_property_guids_to_add,
                                                                         write_property_guids=write_property_guids_to_add)
        return self.set_object_security_descriptor(ad_object_to_modify, current_sd,
                                                   raise_exception_on_failure=raise_exception_on_failure,
                                                   skip_validation=skip_validation)

    def add_permission_to_group_security_descriptor(self, group,
                                                    sids_to_grant_permissions_to: List[Union[
                                                        str, sd_utils.ObjectSid, security_constants.WellKnownSID]],
                                                    access_masks_to_add: List[sd_utils.AccessMask] = None,
                                                    rights_guids_to_add: List[Union[ADRightsGuid, str]] = None,
                                                    read_property_guids_to_add: List[str] = None,
                                                    write_property_guids_to_add: List[str] = None,
                                                    raise_exception_on_failure: bool = True,
                                                    skip_validation: bool = False) -> bool:
        """ Add specified permissions to the security descriptor on a group for specified SIDs.
        This can be used to grant 1 or more other users/groups/computers/etc. the right to take broad actions or narrow
        privileged actions on the group, via adding access masks or rights guids respectively. It can also give
        1 or more users/groups/computers/etc. the ability to read or write specific properties on the group by
        specifying read or write property guids to add.

        This can, as an example, take a group and give another group the right to delete it. Or take a group
        and give a list of computers the right to read the group's SID. Or take a group and let another user
        add members to it. Etc. Etc.

        :param group: An ADGroup or String distinguished name, referring to the group that will have the permissions on
                      it modified.
        :param sids_to_grant_permissions_to: SIDs referring to the other entities that will be given new permissions
                                             on the group. These may be ObjectSID objects, SID strings, or
                                             WellKnownSIDs.
        :param access_masks_to_add: A list of AccessMask objects to grant to the SIDs. These represent broad categories
                                    of actions, such as GENERIC_READ and GENERIC_WRITE.
        :param rights_guids_to_add: A list of rights guids to grant to the SIDs. These may be specified as strings or
                                    as ADRightsGuid enums, and represent narrower permissions to grant to the SIDs for
                                    targeted actions such as Unexpire_Password or Apply_Group_Policy. Some of these
                                    do not make logical sense to use in all contexts, as some rights guids only have
                                    meaning in a self-relative context, or only have meaning on some object types.
                                    It is left up to the caller to decide what is meaningful.
        :param read_property_guids_to_add: A list of property guids that represent properties of the group that the
                                           SIDs will be granted the right to read. These must be strings.
        :param write_property_guids_to_add: A list of property guids that represent properties of the group that the
                                            SIDs will be granted the right to write. These must be strings.
        :param raise_exception_on_failure: A boolean indicating if an exception should be raised if we fail to update
                                           the security descriptor, instead of returning False. defaults to True
        :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                Defaults to False. This can be used to make this function more performant when
                                the caller knows all the distinguished names being specified are valid, as it
                                performs far fewer queries.
        :returns: A boolean indicating if we succeeded in updating the security descriptor.
        :raises: InvalidLdapParameterException if any inputs are the wrong type.
        :raises: ObjectNotFoundException if the a string distinguished name is specified and cannot be found.
        :raises: PermissionDeniedException if we fail to modify the Security Descriptor and raise_exception_on_failure
                 is true
        """
        group = self._validate_group_and_get_group_obj(group, skip_validation=skip_validation)
        return self.add_permission_to_object_security_descriptor(group, sids_to_grant_permissions_to,
                                                                 access_masks_to_add, rights_guids_to_add,
                                                                 read_property_guids_to_add,
                                                                 write_property_guids_to_add,
                                                                 raise_exception_on_failure=raise_exception_on_failure,
                                                                 skip_validation=skip_validation)

    def add_permission_to_user_security_descriptor(self, user: Union[str, ADUser],
                                                   sids_to_grant_permissions_to: List[
                                                       Union[str, sd_utils.ObjectSid, security_constants.WellKnownSID]],
                                                   access_masks_to_add: List[sd_utils.AccessMask] = None,
                                                   rights_guids_to_add: List[Union[ADRightsGuid, str]] = None,
                                                   read_property_guids_to_add: List[str] = None,
                                                   write_property_guids_to_add: List[str] = None,
                                                   raise_exception_on_failure: bool = True,
                                                   skip_validation: bool = False) -> bool:
        """ Add specified permissions to the security descriptor on a user for specified SIDs.
        This can be used to grant 1 or more other users/groups/computers/etc. the right to take broad actions or narrow
        privileged actions on the user, via adding access masks or rights guids respectively. It can also give
        1 or more users/groups/computers/etc. the ability to read or write specific properties on the user by
        specifying read or write property guids to add.

        This can, as an example, take a user and give another user the right to delete it. Or take a user
        and give a list of computers the right to read and write the user's owner SID. Or take a user and let another
        user reset their password without needing the current one. Etc. Etc.

        :param user: An ADUser or String distinguished name, referring to the user that will have the permissions on it
                     modified.
        :param sids_to_grant_permissions_to: SIDs referring to the other entities that will be given new permissions
                                             on the user. These may be ObjectSID objects, SID strings, or
                                             WellKnownSIDs.
        :param access_masks_to_add: A list of AccessMask objects to grant to the SIDs. These represent broad categories
                                    of actions, such as GENERIC_READ and GENERIC_WRITE.
        :param rights_guids_to_add: A list of rights guids to grant to the SIDs. These may be specified as strings or
                                    as ADRightsGuid enums, and represent narrower permissions to grant to the SIDs for
                                    targeted actions such as Unexpire_Password or Apply_Group_Policy. Some of these
                                    do not make logical sense to use in all contexts, as some rights guids only have
                                    meaning in a self-relative context, or only have meaning on some object types.
                                    It is left up to the caller to decide what is meaningful.
        :param read_property_guids_to_add: A list of property guids that represent properties of the user that the
                                           SIDs will be granted the right to read. These must be strings.
        :param write_property_guids_to_add: A list of property guids that represent properties of the user that the
                                            SIDs will be granted the right to write. These must be strings.
        :param raise_exception_on_failure: A boolean indicating if an exception should be raised if we fail to update
                                           the security descriptor, instead of returning False. defaults to True
        :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                Defaults to False. This can be used to make this function more performant when
                                the caller knows all the distinguished names being specified are valid, as it
                                performs far fewer queries.
        :returns: A boolean indicating if we succeeded in updating the security descriptor.
        :raises: InvalidLdapParameterException if any inputs are the wrong type.
        :raises: ObjectNotFoundException if the a string distinguished name is specified and cannot be found.
        :raises: PermissionDeniedException if we fail to modify the Security Descriptor and raise_exception_on_failure
                 is true
        """
        user = self._validate_user_and_get_user_obj(user, skip_validation=skip_validation)
        return self.add_permission_to_object_security_descriptor(user, sids_to_grant_permissions_to,
                                                                 access_masks_to_add, rights_guids_to_add,
                                                                 read_property_guids_to_add,
                                                                 write_property_guids_to_add,
                                                                 raise_exception_on_failure=raise_exception_on_failure,
                                                                 skip_validation=skip_validation)

    def add_permission_to_computer_security_descriptor(self, computer: Union[str, ADComputer],
                                                       sids_to_grant_permissions_to: List[Union[
                                                           str, sd_utils.ObjectSid, security_constants.WellKnownSID]],
                                                       access_masks_to_add: List[sd_utils.AccessMask] = None,
                                                       rights_guids_to_add: List[Union[ADRightsGuid, str]] = None,
                                                       read_property_guids_to_add: List[str] = None,
                                                       write_property_guids_to_add: List[str] = None,
                                                       raise_exception_on_failure: bool = True,
                                                       skip_validation: bool = False) -> bool:
        """ Add specified permissions to the security descriptor on a computer for specified SIDs.
        This can be used to grant 1 or more other users/groups/computers/etc. the right to take broad actions or narrow
        privileged actions on the computer, via adding access masks or rights guids respectively. It can also give
        1 or more users/groups/computers/etc. the ability to read or write specific properties on the user by
        specifying read or write property guids to add.

        This can, as an example, take a computer and give a user the right to delete it. Or take a computer
        and give a list of computers the right to read and write the user's owner SID. Or take a computer and let
        another user reset their password without needing the current one. Etc. Etc.

        :param computer: An ADComputer or String distinguished name, referring to the computer that will have the
                         permissions on it modified.
        :param sids_to_grant_permissions_to: SIDs referring to the other entities that will be given new permissions
                                             on the user. These may be ObjectSID objects, SID strings, or
                                             WellKnownSIDs.
        :param access_masks_to_add: A list of AccessMask objects to grant to the SIDs. These represent broad categories
                                    of actions, such as GENERIC_READ and GENERIC_WRITE.
        :param rights_guids_to_add: A list of rights guids to grant to the SIDs. These may be specified as strings or
                                    as ADRightsGuid enums, and represent narrower permissions to grant to the SIDs for
                                    targeted actions such as Unexpire_Password or Apply_Group_Policy. Some of these
                                    do not make logical sense to use in all contexts, as some rights guids only have
                                    meaning in a self-relative context, or only have meaning on some object types.
                                    It is left up to the caller to decide what is meaningful.
        :param read_property_guids_to_add: A list of property guids that represent properties of the computer that the
                                           SIDs will be granted the right to read. These must be strings.
        :param write_property_guids_to_add: A list of property guids that represent properties of the computer that the
                                            SIDs will be granted the right to write. These must be strings.
        :param raise_exception_on_failure: A boolean indicating if an exception should be raised if we fail to update
                                           the security descriptor, instead of returning False. defaults to True
        :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                Defaults to False. This can be used to make this function more performant when
                                the caller knows all the distinguished names being specified are valid, as it
                                performs far fewer queries.
        :returns: A boolean indicating if we succeeded in updating the security descriptor.
        :raises: InvalidLdapParameterException if any inputs are the wrong type.
        :raises: ObjectNotFoundException if the a string distinguished name is specified and cannot be found.
        :raises: PermissionDeniedException if we fail to modify the Security Descriptor and raise_exception_on_failure
                 is true
        """
        computer = self._validate_computer_and_get_computer_obj(computer, skip_validation=skip_validation)
        return self.add_permission_to_object_security_descriptor(computer, sids_to_grant_permissions_to,
                                                                 access_masks_to_add, rights_guids_to_add,
                                                                 read_property_guids_to_add,
                                                                 write_property_guids_to_add,
                                                                 raise_exception_on_failure=raise_exception_on_failure,
                                                                 skip_validation=skip_validation)

    # Various account management functionalities

    def change_password_for_account(self, account: Union[str, ADUser, ADComputer], new_password: str,
                                    current_password: str, skip_validation: bool = False) -> bool:
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
        :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                Defaults to False. This can be used to make this function more performant when
                                the caller knows all the distinguished names being specified are valid, as it
                                performs far fewer queries.
        :returns: True if the operation succeeds. If the operation fails, either an exception will be raised or False
                  will be returned depending on whether the ldap connection for this session has "raise_exceptions"
                  set to True or not.
        """
        account = self._validate_user_and_get_user_obj(account, can_be_computer=True, skip_validation=skip_validation)
        account_dn = account.distinguished_name
        return self.ldap_connection.extend.microsoft.modify_password(account_dn, new_password, current_password)

    def reset_password_for_account(self, account: Union[str, ADUser, ADComputer], new_password: str,
                                   skip_validation: bool = False) -> bool:
        """ Resets a password for a user (includes computers) to a new desired password.
        To reset a password, a new password is provided to replace the current one without providing the current
        password. This is a privileged operation and maps to the RESET_PASSWORD permission in AD.

        :param account: The account whose password is being changed. This may either be a string account name, to be
                        looked up, or an ADObject object.
        :param new_password: The new password for the account.
        :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                Defaults to False. This can be used to make this function more performant when
                                the caller knows all the distinguished names being specified are valid, as it
                                performs far fewer queries.
        :returns: True if the operation succeeds. If the operation fails, either an exception will be raised or False
                  will be returned depending on whether the ldap connection for this session has "raise_exceptions"
                  set to True or not.
        """
        return self.change_password_for_account(account, new_password, None, skip_validation=skip_validation)

    def disable_account(self, account: Union[str, ADUser, ADComputer]) -> bool:
        """ Disable a user account.
        :param account: The string name of the user/computer account to disable. This may either be a
                        sAMAccountName, a distinguished name, or a unique common name. This can also be an ADObject,
                        and the distinguished name will be extracted from it.
        :returns: True if the operation succeeds. If the operation fails, either an exception will be raised or False
                  will be returned depending on whether the ldap connection for this session has "raise_exceptions"
                  set to True or not.
        """
        # even if we get an object, re-find the account because we need the current userAccountControl
        if isinstance(account, ADObject):
            account = account.distinguished_name

        if isinstance(account, str):
            # this will find users and computers because computers are users
            account_obj = self.find_user_by_name(account, attributes_to_lookup=[
                ldap_constants.AD_ATTRIBUTE_USER_ACCOUNT_CONTROL])
            if account_obj is None:
                raise ObjectNotFoundException('No account could be found with the User object class and name {}'
                                              .format(account))
        else:
            raise InvalidLdapParameterException('The account specified must either be an ADObject object or a string '
                                                'name.')
        account_dn = account_obj.distinguished_name
        current_user_access_control = int(account_obj.get(ldap_constants.AD_ATTRIBUTE_USER_ACCOUNT_CONTROL))
        new_access_control = current_user_access_control | ldap_constants.ACCOUNT_DISABLED
        # if the account is already disabled, this is a no-op
        if current_user_access_control == new_access_control:
            logger.info('Account with distinguished name %s is already disabled. No action is needed',
                        account_dn)
            return True
        changes = {
            ldap_constants.AD_ATTRIBUTE_USER_ACCOUNT_CONTROL: (MODIFY_REPLACE, new_access_control)
        }
        res = self.ldap_connection.modify(account_dn, changes)
        success, result, _, _ = ldap_utils.process_ldap3_conn_return_value(self.ldap_connection, res)

        if not success:
            logger.warning('Result of modifying user account control to disable %s: %s', account_dn, result)
        else:
            logger.debug('Result of modifying user account control to disable %s: %s', account_dn, result)
        return success

    def enable_account(self, account: Union[str, ADComputer, ADUser]) -> bool:
        """ Enable a user account.
        :param account: The string name of the user/computer account to enable. This may either be a
                        sAMAccountName, a distinguished name, or a unique common name. This can also be an ADObject,
                        and the distinguished name will be extracted from it.
        :returns: True if the operation succeeds. If the operation fails, either an exception will be raised or False
                  will be returned depending on whether the ldap connection for this session has "raise_exceptions"
                  set to True or not.
        """
        # even if we get an object, re-find the account because we need the current userAccountControl
        if isinstance(account, ADObject):
            account = account.distinguished_name

        if isinstance(account, str):
            # this will find users and computers because computers are users
            account_obj = self.find_user_by_name(account, attributes_to_lookup=[
                ldap_constants.AD_ATTRIBUTE_USER_ACCOUNT_CONTROL])
            if account_obj is None:
                raise ObjectNotFoundException('No account could be found with the User object class and name {}'
                                              .format(account))
        else:
            raise InvalidLdapParameterException('The account specified must either be an ADObject object or a string '
                                                'name.')
        account_dn = account_obj.distinguished_name
        current_user_access_control = int(account_obj.get(ldap_constants.AD_ATTRIBUTE_USER_ACCOUNT_CONTROL))
        new_access_control = current_user_access_control & ~ldap_constants.ACCOUNT_DISABLED
        # if the account is already enabled, this is a no-op
        if current_user_access_control == new_access_control:
            logger.info('Account with distinguished name %s is already enabled. No action is needed',
                        account_dn)
            return True
        changes = {
            ldap_constants.AD_ATTRIBUTE_USER_ACCOUNT_CONTROL: (MODIFY_REPLACE, new_access_control)
        }
        res = self.ldap_connection.modify(account_dn, changes)
        success, result, _, _ = ldap_utils.process_ldap3_conn_return_value(self.ldap_connection, res)

        if not success:
            logger.warning('Result of modifying user account control to disable %s: %s', account_dn, result)
        else:
            logger.debug('Result of modifying user account control to disable %s: %s', account_dn, result)
        return success

    def unlock_account(self, account: Union[str, ADComputer, ADUser], skip_validation: bool = False) -> bool:
        """ Unlock a user who's been locked out for some period of time.
        :param account: The string name of the user/computer account that has been locked out. This may either be a
                        sAMAccountName, a distinguished name, or a unique common name. This can also be an ADObject,
                        and the distinguished name will be extracted from it.
        :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                Defaults to False. This can be used to make this function more performant when
                                the caller knows all the distinguished names being specified are valid, as it
                                performs far fewer queries.
        :returns: True if the operation succeeds. If the operation fails, either an exception will be raised or False
                  will be returned depending on whether the ldap connection for this session has "raise_exceptions"
                  set to True or not.
        """
        account = self._validate_user_and_get_user_obj(account, can_be_computer=True,
                                                       skip_validation=skip_validation)
        account_dn = account.distinguished_name
        return self.ldap_connection.extend.microsoft.unlock_account(account_dn)

    # generic user, group, and object modification functions

    def _do_something_to_attribute_for_object(self, ad_object: Union[str, ADObject], attribute_to_value_map: dict,
                                              controls: List[Control], raise_exception_on_failure: bool,
                                              action: str, action_desc_for_errors: str, skip_validation: bool = False):
        """ Our helper function for either atomically appending to, or overwriting attributes on an object.

        :param ad_object: Either an ADObject object or string distinguished name referencing the object to be modified.
        :param attribute_to_value_map: A dictionary mapping string LDAP attribute names to values that will be used
                                       in the modification operation. Values may either be primitives, such as strings,
                                       bytes, and numbers if a single value will be set or appended. Values may
                                       also be iterables such as sets and lists if a multi-valued parameter will be
                                       set or if multiple values will be appended to it.
        :param controls: LDAP controls to use during the modification operation.
        :param raise_exception_on_failure: If true, an exception will be raised with additional details if the modify
                                           fails.
        :param action: The action to take - either MODIFY_ADD or MODIFY_REPLACE
        :param action_desc_for_errors: A description of what we're doing for use in errors.
        :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                Defaults to False. This can be used to make this function more performant when
                                the caller knows all the distinguished names being specified are valid, as it
                                performs far fewer queries.
        :returns: True if the operation succeeds, False otherwise.
        :raises: InvalidLdapParameterException if any attributes or values are malformed.
        :raises: ObjectNotFoundException if a distinguished name is specified and cannot be found
        :raises: AttributeModificationException if raise_exception_on_failure is True and we fail
        :raises: Other LDAP exceptions from the ldap3 library if the connection is configured to raise exceptions and
                 issues are seen such as determining that a value is malformed based on the server schema.
        """
        ad_object = self._validate_obj_and_get_ad_obj(ad_object, skip_validation=skip_validation)
        object_dn = ad_object.distinguished_name

        # format all of the changes provided by users so they're ready to serialize for an ldap message,
        # and do some validation
        changes_dict = {}
        for key, value in attribute_to_value_map.items():
            if not isinstance(key, str):
                raise InvalidLdapParameterException('The attributes specified must all be string LDAP attributes. {} '
                                                    'is not.'.format(key))
            if value is None:
                raise InvalidLdapParameterException('Null values may not be specified when {}. A null '
                                                    'value was specified for {}.'.format(action_desc_for_errors, key))
            changes_dict[key] = (action, ldap_utils.convert_to_ldap_iterable(value))
        # do the modification. do not log our values in case they're sensitive (e.g. passwords)
        logger.debug('Attempting modification of attributes %s for distinguished name %s',
                     changes_dict.keys(), object_dn)
        res = self.ldap_connection.modify(object_dn, changes_dict, controls=controls)
        success, result, response, _ = ldap_utils.process_ldap3_conn_return_value(self.ldap_connection, res,
                                                                                  paginated_response=False)
        # raise an exception with LDAP details that might be useful to the caller (e.g. bad format of attribute,
        # insufficient permissions, unwilling to perform due to constraint violation)
        if raise_exception_on_failure and not success:
            raise AttributeModificationException('Failed when {} for the object within the domain. LDAP result: {}'
                                                 .format(action_desc_for_errors, result))
        return success

    def atomic_append_to_attribute_for_object(self, ad_object: Union[str, ADObject], attribute: str, value,
                                              controls: List[Control] = None, raise_exception_on_failure: bool = True,
                                              skip_validation: bool = False) -> bool:
        """ Atomically append a value to an attribute for an object in the domain.

        :param ad_object: Either an ADObject object or string distinguished name referencing the object to be modified.
        :param attribute: A string specifying the name of the LDAP attribute to be appended to.
        :param value: The value to append to the attribute. Value may either be a primitive, such as a string, bytes,
                      or a number, if a single value will be appended. Value may also be an iterable such as a set or
                      a list if a multi-valued attribute will be appended to, in order to append multiple new values
                      to it at once.
        :param controls: LDAP controls to use during the modification operation.
        :param raise_exception_on_failure: If true, an exception will be raised with additional details if the modify
                                           fails.
        :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                Defaults to False. This can be used to make this function more performant when
                                the caller knows all the distinguished names being specified are valid, as it
                                performs far fewer queries.
        :returns: True if the operation succeeds, False otherwise.
        :raises: InvalidLdapParameterException if any attributes or values are malformed.
        :raises: ObjectNotFoundException if a distinguished name is specified and cannot be found
        :raises: AttributeModificationException if raise_exception_on_failure is True and we fail
        :raises: Other LDAP exceptions from the ldap3 library if the connection is configured to raise exceptions and
                 issues are seen such as determining that a value is malformed based on the server schema.
        """
        attr_map = {attribute: value}
        return self._do_something_to_attribute_for_object(ad_object, attr_map, controls, raise_exception_on_failure,
                                                          MODIFY_ADD, 'appending a value for an attribute',
                                                          skip_validation=skip_validation)

    def atomic_append_to_attributes_for_object(self, ad_object: Union[str, ADObject], attribute_to_value_map: dict,
                                               controls: List[Control] = None, raise_exception_on_failure: bool = True,
                                               skip_validation: bool = False) -> bool:
        """ Atomically append values to multiple attributes for an object in the domain.

        :param ad_object: Either an ADObject object or string distinguished name referencing the object to be modified.
        :param attribute_to_value_map: A dictionary mapping string LDAP attribute names to values that will be used
                                       in the modification operation. Values may either be primitives, such as strings,
                                       bytes, and numbers if a single value will be appended. Values may
                                       also be iterables such as sets and lists if multiple values will be appended
                                       to the attributes.
        :param controls: LDAP controls to use during the modification operation.
        :param raise_exception_on_failure: If true, an exception will be raised with additional details if the modify
                                           fails.
        :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                Defaults to False. This can be used to make this function more performant when
                                the caller knows all the distinguished names being specified are valid, as it
                                performs far fewer queries.
        :returns: True if the operation succeeds, False otherwise.
        :raises: InvalidLdapParameterException if any attributes or values are malformed.
        :raises: ObjectNotFoundException if a distinguished name is specified and cannot be found
        :raises: AttributeModificationException if raise_exception_on_failure is True and we fail
        :raises: Other LDAP exceptions from the ldap3 library if the connection is configured to raise exceptions and
                 issues are seen such as determining that a value is malformed based on the server schema.
        """
        return self._do_something_to_attribute_for_object(ad_object, attribute_to_value_map, controls,
                                                          raise_exception_on_failure, MODIFY_ADD,
                                                          'appending values for multiple attributes',
                                                          skip_validation=skip_validation)

    def overwrite_attribute_for_object(self, ad_object: Union[str, ADObject], attribute: str, value,
                                       controls: List[Control] = None, raise_exception_on_failure: bool = True,
                                       skip_validation: bool = False) -> bool:
        """ Atomically overwrite the value of an attribute for an object in the domain.

        :param ad_object: Either an ADObject object or string distinguished name referencing the object to be modified.
        :param attribute: A string specifying the name of the LDAP attribute to be overwritten.
        :param value: The value to set for the attribute. Value may either be a primitive, such as a string, bytes,
                      or a number, if a single value will be set. Value may also be an iterable such as a set or
                      a list if a multi-valued attribute will be set.
        :param controls: LDAP controls to use during the modification operation.
        :param raise_exception_on_failure: If true, an exception will be raised with additional details if the modify
                                           fails.
        :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                Defaults to False. This can be used to make this function more performant when
                                the caller knows all the distinguished names being specified are valid, as it
                                performs far fewer queries.
        :returns: True if the operation succeeds, False otherwise.
        :raises: InvalidLdapParameterException if any attributes or values are malformed.
        :raises: ObjectNotFoundException if a distinguished name is specified and cannot be found
        :raises: AttributeModificationException if raise_exception_on_failure is True and we fail
        :raises: Other LDAP exceptions from the ldap3 library if the connection is configured to raise exceptions and
                 issues are seen such as determining that a value is malformed based on the server schema.
        """
        attr_map = {attribute: value}
        return self._do_something_to_attribute_for_object(ad_object, attr_map, controls,
                                                          raise_exception_on_failure, MODIFY_REPLACE,
                                                          'overwriting a value for an attributes',
                                                          skip_validation=skip_validation)

    def overwrite_attributes_for_object(self, ad_object: Union[str, ADObject], attribute_to_value_map: dict,
                                        controls: List[Control] = None, raise_exception_on_failure: bool = True,
                                        skip_validation: bool = False) -> bool:
        """ Atomically overwrite values of multiple attributes for an object in the domain.

        :param ad_object: Either an ADObject object or string distinguished name referencing the object to be modified.
        :param attribute_to_value_map: A dictionary mapping string LDAP attribute names to values that will be used
                                       in the modification operation. Values may either be primitives, such as strings,
                                       bytes, and numbers if a single value will set. Values may also be iterables
                                       such as sets and lists if an attribute is multi-valued and multiple values will
                                       be set.
        :param controls: LDAP controls to use during the modification operation.
        :param raise_exception_on_failure: If true, an exception will be raised with additional details if the modify
                                           fails.
        :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                Defaults to False. This can be used to make this function more performant when
                                the caller knows all the distinguished names being specified are valid, as it
                                performs far fewer queries.
        :returns: True if the operation succeeds, False otherwise.
        :raises: InvalidLdapParameterException if any attributes or values are malformed.
        :raises: ObjectNotFoundException if a distinguished name is specified and cannot be found
        :raises: AttributeModificationException if raise_exception_on_failure is True and we fail
        :raises: Other LDAP exceptions from the ldap3 library if the connection is configured to raise exceptions and
                 issues are seen such as determining that a value is malformed based on the server schema.
        """
        return self._do_something_to_attribute_for_object(ad_object, attribute_to_value_map, controls,
                                                          raise_exception_on_failure, MODIFY_REPLACE,
                                                          'overwriting values for multiple attributes',
                                                          skip_validation=skip_validation)

    def atomic_append_to_attribute_for_group(self, group: Union[str, ADGroup], attribute: str, value,
                                             controls: List[Control] = None, raise_exception_on_failure: bool = True,
                                             skip_validation: bool = False) -> bool:
        """ Atomically append a value to an attribute for a group in the domain.

        :param group: Either an ADGroup object or string name referencing the group to be modified.
        :param attribute: A string specifying the name of the LDAP attribute to be appended to.
        :param value: The value to append to the attribute. Value may either be a primitive, such as a string, bytes,
                      or a number, if a single value will be appended. Value may also be an iterable such as a set or
                      a list if a multi-valued attribute will be appended to, in order to append multiple new values
                      to it at once.
        :param controls: LDAP controls to use during the modification operation.
        :param raise_exception_on_failure: If true, an exception will be raised with additional details if the modify
                                           fails.
        :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                Defaults to False. This can be used to make this function more performant when
                                the caller knows all the distinguished names being specified are valid, as it
                                performs far fewer queries.
        :returns: True if the operation succeeds, False otherwise.
        :raises: InvalidLdapParameterException if any attributes or values are malformed.
        :raises: ObjectNotFoundException if a distinguished name is specified and cannot be found
        :raises: AttributeModificationException if raise_exception_on_failure is True and we fail
        :raises: Other LDAP exceptions from the ldap3 library if the connection is configured to raise exceptions and
                 issues are seen such as determining that a value is malformed based on the server schema.
        """
        group = self._validate_group_and_get_group_obj(group, skip_validation=skip_validation)
        return self.atomic_append_to_attribute_for_object(group, attribute, value, controls,
                                                          raise_exception_on_failure)

    def atomic_append_to_attributes_for_group(self, group: Union[str, ADGroup], attribute_to_value_map: dict,
                                              controls: List[Control] = None, raise_exception_on_failure: bool = True,
                                              skip_validation: bool = False) -> bool:
        """ Atomically append values to multiple attributes for a group in the domain.

        :param group: Either an ADGroup object or string name referencing the group to be modified.
        :param attribute_to_value_map: A dictionary mapping string LDAP attribute names to values that will be used
                                       in the modification operation. Values may either be primitives, such as strings,
                                       bytes, and numbers if a single value will be appended. Values may
                                       also be iterables such as sets and lists if multiple values will be appended
                                       to the attributes.
        :param controls: LDAP controls to use during the modification operation.
        :param raise_exception_on_failure: If true, an exception will be raised with additional details if the modify
                                           fails.
        :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                Defaults to False. This can be used to make this function more performant when
                                the caller knows all the distinguished names being specified are valid, as it
                                performs far fewer queries.
        :returns: True if the operation succeeds, False otherwise.
        :raises: InvalidLdapParameterException if any attributes or values are malformed.
        :raises: ObjectNotFoundException if a distinguished name is specified and cannot be found
        :raises: AttributeModificationException if raise_exception_on_failure is True and we fail
        :raises: Other LDAP exceptions from the ldap3 library if the connection is configured to raise exceptions and
                 issues are seen such as determining that a value is malformed based on the server schema.
        """
        group = self._validate_group_and_get_group_obj(group)
        return self.atomic_append_to_attributes_for_object(group, attribute_to_value_map, controls,
                                                           raise_exception_on_failure, skip_validation=skip_validation)

    def overwrite_attribute_for_group(self, group: Union[str, ADGroup], attribute: str, value,
                                      controls: List[Control] = None, raise_exception_on_failure: bool = True,
                                      skip_validation: bool = False) -> bool:
        """ Atomically overwrite the value of an attribute for a group in the domain.

        :param group: Either an ADUser object or string name referencing the group to be modified.
        :param attribute: A string specifying the name of the LDAP attribute to be overwritten.
        :param value: The value to set for the attribute. Value may either be a primitive, such as a string, bytes,
                      or a number, if a single value will be set. Value may also be an iterable such as a set or
                      a list if a multi-valued attribute will be set.
        :param controls: LDAP controls to use during the modification operation.
        :param raise_exception_on_failure: If true, an exception will be raised with additional details if the modify
                                           fails.
        :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                Defaults to False. This can be used to make this function more performant when
                                the caller knows all the distinguished names being specified are valid, as it
                                performs far fewer queries.
        :returns: True if the operation succeeds, False otherwise.
        :raises: InvalidLdapParameterException if any attributes or values are malformed.
        :raises: ObjectNotFoundException if a distinguished name is specified and cannot be found
        :raises: AttributeModificationException if raise_exception_on_failure is True and we fail
        :raises: Other LDAP exceptions from the ldap3 library if the connection is configured to raise exceptions and
                 issues are seen such as determining that a value is malformed based on the server schema.
        """
        group = self._validate_group_and_get_group_obj(group, skip_validation=skip_validation)
        return self.overwrite_attribute_for_object(group, attribute, value, controls,
                                                   raise_exception_on_failure, skip_validation=skip_validation)

    def overwrite_attributes_for_group(self, group: Union[str, ADGroup], attribute_to_value_map: dict,
                                       controls: List[Control] = None, raise_exception_on_failure: bool = True,
                                       skip_validation: bool = False) -> bool:
        """ Atomically overwrite values of multiple attributes for a group in the domain.

        :param group: Either an ADGroup object or string name referencing the group to have attributes overwritten.
        :param attribute_to_value_map: A dictionary mapping string LDAP attribute names to values that will be used
                                       in the modification operation. Values may either be primitives, such as strings,
                                       bytes, and numbers if a single value will set. Values may also be iterables
                                       such as sets and lists if an attribute is multi-valued and multiple values will
                                       be set.
        :param controls: LDAP controls to use during the modification operation.
        :param raise_exception_on_failure: If true, an exception will be raised with additional details if the modify
                                           fails.
        :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                Defaults to False. This can be used to make this function more performant when
                                the caller knows all the distinguished names being specified are valid, as it
                                performs far fewer queries.
        :returns: True if the operation succeeds, False otherwise.
        :raises: InvalidLdapParameterException if any attributes or values are malformed.
        :raises: ObjectNotFoundException if a name is specified and cannot be found
        :raises: AttributeModificationException if raise_exception_on_failure is True and we fail
        :raises: Other LDAP exceptions from the ldap3 library if the connection is configured to raise exceptions and
                 issues are seen such as determining that a value is malformed based on the server schema.
        """
        group = self._validate_group_and_get_group_obj(group, skip_validation=skip_validation)
        return self.overwrite_attributes_for_object(group, attribute_to_value_map, controls,
                                                    raise_exception_on_failure, skip_validation=skip_validation)

    def atomic_append_to_attribute_for_user(self, user: Union[str, ADUser], attribute: str, value,
                                            controls: List[Control] = None, raise_exception_on_failure: bool = True,
                                            skip_validation: bool = False) -> bool:
        """ Atomically append a value to an attribute for a user in the domain.

        :param user: Either an ADUser object or string name referencing the user to be modified.
        :param attribute: A string specifying the name of the LDAP attribute to be appended to.
        :param value: The value to append to the attribute. Value may either be a primitive, such as a string, bytes,
                      or a number, if a single value will be appended. Value may also be an iterable such as a set or
                      a list if a multi-valued attribute will be appended to, in order to append multiple new values
                      to it at once.
        :param controls: LDAP controls to use during the modification operation.
        :param raise_exception_on_failure: If true, an exception will be raised with additional details if the modify
                                           fails.
        :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                Defaults to False. This can be used to make this function more performant when
                                the caller knows all the distinguished names being specified are valid, as it
                                performs far fewer queries.
        :returns: True if the operation succeeds, False otherwise.
        :raises: InvalidLdapParameterException if any attributes or values are malformed.
        :raises: ObjectNotFoundException if a distinguished name is specified and cannot be found
        :raises: AttributeModificationException if raise_exception_on_failure is True and we fail
        :raises: Other LDAP exceptions from the ldap3 library if the connection is configured to raise exceptions and
                 issues are seen such as determining that a value is malformed based on the server schema.
        """
        user = self._validate_user_and_get_user_obj(user, skip_validation=skip_validation)
        return self.atomic_append_to_attribute_for_object(user, attribute, value, controls,
                                                          raise_exception_on_failure,
                                                          skip_validation=skip_validation)

    def atomic_append_to_attributes_for_user(self, user: Union[str, ADUser], attribute_to_value_map: dict,
                                             controls: List[Control] = None, raise_exception_on_failure: bool = True,
                                             skip_validation: bool = False) -> bool:
        """ Atomically append values to multiple attributes for a user in the domain.

        :param user: Either an ADUser object or string name referencing the user to be modified.
        :param attribute_to_value_map: A dictionary mapping string LDAP attribute names to values that will be used
                                       in the modification operation. Values may either be primitives, such as strings,
                                       bytes, and numbers if a single value will be appended. Values may
                                       also be iterables such as sets and lists if multiple values will be appended
                                       to the attributes.
        :param controls: LDAP controls to use during the modification operation.
        :param raise_exception_on_failure: If true, an exception will be raised with additional details if the modify
                                           fails.
        :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                Defaults to False. This can be used to make this function more performant when
                                the caller knows all the distinguished names being specified are valid, as it
                                performs far fewer queries.
        :returns: True if the operation succeeds, False otherwise.
        :raises: InvalidLdapParameterException if any attributes or values are malformed.
        :raises: ObjectNotFoundException if a distinguished name is specified and cannot be found
        :raises: AttributeModificationException if raise_exception_on_failure is True and we fail
        :raises: Other LDAP exceptions from the ldap3 library if the connection is configured to raise exceptions and
                 issues are seen such as determining that a value is malformed based on the server schema.
        """
        user = self._validate_user_and_get_user_obj(user, skip_validation=skip_validation)
        return self.atomic_append_to_attributes_for_object(user, attribute_to_value_map, controls,
                                                           raise_exception_on_failure, skip_validation=skip_validation)

    def overwrite_attribute_for_user(self, user: Union[str, ADUser], attribute: str, value,
                                     controls: List[Control] = None, raise_exception_on_failure: bool = True,
                                     skip_validation: bool = False) -> bool:
        """ Atomically overwrite the value of an attribute for a user in the domain.

        :param user: Either an ADUser object or string name referencing the user to be modified.
        :param attribute: A string specifying the name of the LDAP attribute to be overwritten.
        :param value: The value to set for the attribute. Value may either be a primitive, such as a string, bytes,
                      or a number, if a single value will be set. Value may also be an iterable such as a set or
                      a list if a multi-valued attribute will be set.
        :param controls: LDAP controls to use during the modification operation.
        :param raise_exception_on_failure: If true, an exception will be raised with additional details if the modify
                                           fails.
        :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                Defaults to False. This can be used to make this function more performant when
                                the caller knows all the distinguished names being specified are valid, as it
                                performs far fewer queries.
        :returns: True if the operation succeeds, False otherwise.
        :raises: InvalidLdapParameterException if any attributes or values are malformed.
        :raises: ObjectNotFoundException if a distinguished name is specified and cannot be found
        :raises: AttributeModificationException if raise_exception_on_failure is True and we fail
        :raises: Other LDAP exceptions from the ldap3 library if the connection is configured to raise exceptions and
                 issues are seen such as determining that a value is malformed based on the server schema.
        """
        user = self._validate_user_and_get_user_obj(user, skip_validation=skip_validation)
        return self.overwrite_attribute_for_object(user, attribute, value, controls,
                                                   raise_exception_on_failure, skip_validation=skip_validation)

    def overwrite_attributes_for_user(self, user: Union[str, ADUser], attribute_to_value_map: dict,
                                      controls: List[Control] = None, raise_exception_on_failure: bool = True,
                                      skip_validation: bool = False) -> bool:
        """ Atomically overwrite values of multiple attributes for a user in the domain.

        :param user: Either an ADUser object or string name referencing the user to have attributes overwritten.
        :param attribute_to_value_map: A dictionary mapping string LDAP attribute names to values that will be used
                                       in the modification operation. Values may either be primitives, such as strings,
                                       bytes, and numbers if a single value will set. Values may also be iterables
                                       such as sets and lists if an attribute is multi-valued and multiple values will
                                       be set.
        :param controls: LDAP controls to use during the modification operation.
        :param raise_exception_on_failure: If true, an exception will be raised with additional details if the modify
                                           fails.
        :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                Defaults to False. This can be used to make this function more performant when
                                the caller knows all the distinguished names being specified are valid, as it
                                performs far fewer queries.
        :returns: True if the operation succeeds, False otherwise.
        :raises: InvalidLdapParameterException if any attributes or values are malformed.
        :raises: ObjectNotFoundException if a name is specified and cannot be found
        :raises: AttributeModificationException if raise_exception_on_failure is True and we fail
        :raises: Other LDAP exceptions from the ldap3 library if the connection is configured to raise exceptions and
                 issues are seen such as determining that a value is malformed based on the server schema.
        """
        user = self._validate_user_and_get_user_obj(user, skip_validation=skip_validation)
        return self.overwrite_attributes_for_object(user, attribute_to_value_map, controls,
                                                    raise_exception_on_failure, skip_validation=skip_validation)

    def atomic_append_to_attribute_for_computer(self, computer: Union[str, ADComputer], attribute: str, value,
                                                controls: List[Control] = None, raise_exception_on_failure: bool = True,
                                                skip_validation: bool = False) -> bool:
        """ Atomically append a value to an attribute for a computer in the domain.

        :param computer: Either an ADComputer object or string name referencing the computer to be modified.
        :param attribute: A string specifying the name of the LDAP attribute to be appended to.
        :param value: The value to append to the attribute. Value may either be a primitive, such as a string, bytes,
                      or a number, if a single value will be appended. Value may also be an iterable such as a set or
                      a list if a multi-valued attribute will be appended to, in order to append multiple new values
                      to it at once.
        :param controls: LDAP controls to use during the modification operation.
        :param raise_exception_on_failure: If true, an exception will be raised with additional details if the modify
                                           fails.
        :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                Defaults to False. This can be used to make this function more performant when
                                the caller knows all the distinguished names being specified are valid, as it
                                performs far fewer queries.
        :returns: True if the operation succeeds, False otherwise.
        :raises: InvalidLdapParameterException if any attributes or values are malformed.
        :raises: ObjectNotFoundException if a distinguished name is specified and cannot be found
        :raises: AttributeModificationException if raise_exception_on_failure is True and we fail
        :raises: Other LDAP exceptions from the ldap3 library if the connection is configured to raise exceptions and
                 issues are seen such as determining that a value is malformed based on the server schema.
        """
        computer = self._validate_computer_and_get_computer_obj(computer, skip_validation=skip_validation)
        return self.atomic_append_to_attribute_for_object(computer, attribute, value, controls,
                                                          raise_exception_on_failure, skip_validation=skip_validation)

    def atomic_append_to_attributes_for_computer(self, computer: Union[str, ADComputer], attribute_to_value_map: dict,
                                                 controls: List[Control] = None,
                                                 raise_exception_on_failure: bool = True,
                                                 skip_validation: bool = False) -> bool:
        """ Atomically append values to multiple attributes for a computer in the domain.

        :param computer: Either an ADComputer object or string name referencing the computer to be modified.
        :param attribute_to_value_map: A dictionary mapping string LDAP attribute names to values that will be used
                                       in the modification operation. Values may either be primitives, such as strings,
                                       bytes, and numbers if a single value will be appended. Values may
                                       also be iterables such as sets and lists if multiple values will be appended
                                       to the attributes.
        :param controls: LDAP controls to use during the modification operation.
        :param raise_exception_on_failure: If true, an exception will be raised with additional details if the modify
                                           fails.
        :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                Defaults to False. This can be used to make this function more performant when
                                the caller knows all the distinguished names being specified are valid, as it
                                performs far fewer queries.
        :returns: True if the operation succeeds, False otherwise.
        :raises: InvalidLdapParameterException if any attributes or values are malformed.
        :raises: ObjectNotFoundException if a distinguished name is specified and cannot be found
        :raises: AttributeModificationException if raise_exception_on_failure is True and we fail
        :raises: Other LDAP exceptions from the ldap3 library if the connection is configured to raise exceptions and
                 issues are seen such as determining that a value is malformed based on the server schema.
        """
        computer = self._validate_computer_and_get_computer_obj(computer, skip_validation=skip_validation)
        return self.atomic_append_to_attributes_for_object(computer, attribute_to_value_map, controls,
                                                           raise_exception_on_failure, skip_validation=skip_validation)

    def overwrite_attribute_for_computer(self, computer: Union[str, ADComputer], attribute: str, value,
                                         controls: List[Control] = None, raise_exception_on_failure: bool = True,
                                         skip_validation: bool = False) -> bool:
        """ Atomically overwrite the value of an attribute for a computer in the domain.

        :param computer: Either an ADComputer object or string name referencing the computer to be modified.
        :param attribute: A string specifying the name of the LDAP attribute to be overwritten.
        :param value: The value to set for the attribute. Value may either be a primitive, such as a string, bytes,
                      or a number, if a single value will be set. Value may also be an iterable such as a set or
                      a list if a multi-valued attribute will be set.
        :param controls: LDAP controls to use during the modification operation.
        :param raise_exception_on_failure: If true, an exception will be raised with additional details if the modify
                                           fails.
        :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                Defaults to False. This can be used to make this function more performant when
                                the caller knows all the distinguished names being specified are valid, as it
                                performs far fewer queries.
        :returns: True if the operation succeeds, False otherwise.
        :raises: InvalidLdapParameterException if any attributes or values are malformed.
        :raises: ObjectNotFoundException if a distinguished name is specified and cannot be found
        :raises: AttributeModificationException if raise_exception_on_failure is True and we fail
        :raises: Other LDAP exceptions from the ldap3 library if the connection is configured to raise exceptions and
                 issues are seen such as determining that a value is malformed based on the server schema.
        """
        computer = self._validate_computer_and_get_computer_obj(computer, skip_validation=skip_validation)
        return self.overwrite_attribute_for_object(computer, attribute, value, controls,
                                                   raise_exception_on_failure, skip_validation=skip_validation)

    def overwrite_attributes_for_computer(self, computer: Union[str, ADComputer], attribute_to_value_map: dict,
                                          controls: List[Control] = None, raise_exception_on_failure: bool = True,
                                          skip_validation: bool = False) -> bool:
        """ Atomically overwrite values of multiple attributes for a computer in the domain.

        :param computer: Either an ADComputer object or string name referencing the computer to have attributes
                         overwritten.
        :param attribute_to_value_map: A dictionary mapping string LDAP attribute names to values that will be used
                                       in the modification operation. Values may either be primitives, such as strings,
                                       bytes, and numbers if a single value will set. Values may also be iterables
                                       such as sets and lists if an attribute is multi-valued and multiple values will
                                       be set.
        :param controls: LDAP controls to use during the modification operation.
        :param raise_exception_on_failure: If true, an exception will be raised with additional details if the modify
                                           fails.
        :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                Defaults to False. This can be used to make this function more performant when
                                the caller knows all the distinguished names being specified are valid, as it
                                performs far fewer queries.
        :returns: True if the operation succeeds, False otherwise.
        :raises: InvalidLdapParameterException if any attributes or values are malformed.
        :raises: ObjectNotFoundException if a name is specified and cannot be found
        :raises: AttributeModificationException if raise_exception_on_failure is True and we fail
        :raises: Other LDAP exceptions from the ldap3 library if the connection is configured to raise exceptions and
                 issues are seen such as determining that a value is malformed based on the server schema.
        """
        computer = self._validate_computer_and_get_computer_obj(computer, skip_validation=skip_validation)
        return self.overwrite_attributes_for_object(computer, attribute_to_value_map, controls,
                                                    raise_exception_on_failure, skip_validation=skip_validation)

    # generic utilities for figuring out information about the current user with respect to the domain
    # and managing trusts

    def create_transfer_sessions_to_all_trusted_domains(self,
                                                        ignore_and_remove_failed_transfers=False) -> List['ADSession']:
        """ Create transfer sessions to all of the different active directory domains that trust the domain used for
        this session.

        :param ignore_and_remove_failed_transfers: If true, failures to transfer the session to a trusted domain will
                                                   be ignored, and will be excluded from results. If false, errors will
                                                   be raised by failed transfers. Defaults to false.
        :returns: A list of ADSession objects representing the transferred authentication to the trusted domains.
        :raises: Other LDAP exceptions if the attempt to bind the transfer session in the trusted domain fails due to
                 authentication issues (e.g. trying to use a non-transitive trust when transferring a user that is
                 not from the primary domain, transferring across a one-way trust when skipping validation,
                 transferring to a domain using SID filtering to restrict cross-domain users)
        """
        # SIMPLE authentication can't transfer between trusts.
        if self.ldap_connection.authentication == SIMPLE:
            raise SessionTransferException('Active Directory sessions using SIMPLE authentication cannot be '
                                           'transferred to trusted domains. Either NTLM or some form of SASL (e.g. '
                                           'Kerberos) must be used.')

        trusted_domains = self.find_trusted_domains_for_domain()
        ad_transferable_domains = [trusted_dom for trusted_dom in trusted_domains
                                   if trusted_dom.is_active_directory_domain_trust()]
        # if this session's user is from the domain that this session exists with, filter further to only domains
        # that trust that domain
        if self.is_session_user_from_domain():
            ad_transferable_domains = [trusted_dom for trusted_dom in ad_transferable_domains
                                       if trusted_dom.trusts_primary_domain()]
        logger.info('Transferring session to %s domains', len(ad_transferable_domains))
        transferred_sessions = []
        for trusted_dom in ad_transferable_domains:
            try:
                transferred_sessions.append(trusted_dom.create_transfer_session_to_trusted_domain(self))
            except:
                if ignore_and_remove_failed_transfers:
                    continue
                raise
        return transferred_sessions

    def is_session_user_from_domain(self) -> bool:
        """ Return a boolean indicating whether or not the session's user is a member of the domain that we're
        communicating with, or is trusted from another domain.
        :returns: True if the user is from the domain we're communicating with, False otherwise.
        """
        authz_id = self.who_am_i()
        if not authz_id:  # anonymous users don't belong to the domain
            return False
        netbios_name = self.domain.find_netbios_name(self.ldap_connection)
        # cast things to uppercase to be safe on the check since domain names aren't case sensitive
        domain_member_netbios_start = 'U:' + netbios_name.upper() + '\\'
        return authz_id.upper().startswith(domain_member_netbios_start)

    def who_am_i(self) -> str:
        """ Return the authorization identity of the session's user as recognized by the server.
        This can be helpful when a script is provided with an identity in one form that is used to start a session
        (e.g. a distinguished name, or a pre-populated kerberos cache) and then it wants to determine its identity
        that the server actually sees.
        This just calls the LDAP connection function, as it's suitable for AD as well.
        :returns: A string indicating the authorization identity of the session's user as recognized by the server.
        """
        return self.ldap_connection.extend.standard.who_am_i()

    # internal validation utils

    def _validate_group_and_get_group_obj(self, group: Union[str, ADGroup], skip_validation=False) -> ADGroup:
        if isinstance(group, str):
            if skip_validation:
                return ADGroup(group, {}, self.domain)
            # do one lookup for existence for better errors
            original = group
            group = self.find_group_by_name(group)
            if group is None:
                raise ObjectNotFoundException('No group could be found with the Group object class and name {}'
                                              .format(original))
        elif not isinstance(group, ADGroup):
            raise InvalidLdapParameterException('The user specified must be an ADGroup object or a string group name.')
        return group

    def _validate_obj_and_get_ad_obj(self, ad_object: Union[str, ADObject], skip_validation=False) -> ADObject:
        # get distinguished name and confirm object existence as needed
        if isinstance(ad_object, str):
            if skip_validation:
                return ADObject(ad_object, {}, self.domain)
            object_dn = ad_object
            if not ldap_utils.is_dn(ad_object):
                raise InvalidLdapParameterException('The object specified must be an ADObject object or a string '
                                                    'distinguished name.')
            # do one lookup for existence for better errors
            res = self._find_ad_objects_and_attrs(object_dn, ldap_constants.FIND_ANYTHING_FILTER,
                                                  BASE, [], 1, ADObject, None)
            if not res:
                raise ObjectNotFoundException('No object could be found with distinguished name {}'.format(ad_object))
            ad_object = res[0]
        elif not isinstance(ad_object, ADObject):
            raise InvalidLdapParameterException('The object specified must be an ADObject object or a string '
                                                'distinguished name.')
        return ad_object

    def _validate_user_and_get_user_obj(self, user: Union[str, ADUser], can_be_computer=False,  # computers are users
                                        skip_validation=False) -> Union[ADUser, ADComputer]:
        if isinstance(user, str):
            if skip_validation:
                return ADUser(user, {}, self.domain)
            # do one lookup for existence for better errors
            original = user
            # computers are users so this will actually work whether can_be_computer is true or false
            user = self.find_user_by_name(user)
            if user is None:
                raise ObjectNotFoundException('No user could be found with the User object class and name {}'
                                              .format(original))
        elif not isinstance(user, ADUser):
            if can_be_computer and isinstance(user, ADComputer):
                return user
            raise InvalidLdapParameterException('The user specified must be an ADUser object or a string user name.')
        return user

    def _validate_computer_and_get_computer_obj(self, computer: Union[str, ADComputer],
                                                skip_validation=False) -> ADComputer:
        if isinstance(computer, str):
            if skip_validation:
                return ADComputer(computer, {}, self.domain)
            # do one lookup for existence for better errors
            original = computer
            computer = self.find_computer_by_name(computer)
            if computer is None:
                raise ObjectNotFoundException('No computer could be found with the Computer object class and name {}'
                                              .format(original))
        elif not isinstance(computer, ADComputer):
            raise InvalidLdapParameterException('The computer specified must be an ADComputer object or a string '
                                                'computer name.')
        return computer

    def __repr__(self):
        conn_repr = self.ldap_connection.__repr__()
        domain_repr = self.domain.__repr__()
        return (
            'ADSession(ldap_connection={}, domain={}, search_paging_size={}, trusted_domain_cache_lifetime_seconds={})'
            .format(conn_repr, domain_repr, self.search_paging_size, self.trusted_domain_cache_lifetime_seconds))

    def __str__(self):
        return self.__repr__()
