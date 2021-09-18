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

from ms_active_directory import logging_utils

from typing import List, TYPE_CHECKING

if TYPE_CHECKING:
    from ms_active_directory.core.ad_domain import ADDomain

from ms_active_directory.core.ad_kerberos_keys import (
    GssKerberosKey,
)
from ms_active_directory.environment.kerberos.kerberos_constants import (
    AD_DEFAULT_NAME_TYPE
)
from ms_active_directory.environment.kerberos.kerberos_keytab_generator import (
    write_gss_kerberos_key_list_to_raw_bytes
)
from ms_active_directory.environment.kerberos.kerberos_keytab_ingester import (
    process_keytab_file_to_extract_entries
)
from ms_active_directory.environment.kerberos.kerberos_raw_key_generator import (
    ad_password_string_to_key
)
from ms_active_directory.environment.ldap.ldap_format_utils import (
    construct_object_distinguished_name
)
from ms_active_directory.environment.security.security_config_constants import (
    ADEncryptionType,
    ENCRYPTION_TYPE_STR_TO_ENUM,
)
from ms_active_directory.exceptions import InvalidComputerParameterException

logger = logging_utils.get_logger()


class ManagedADObject:

    def __init__(self, samaccount_name: str, domain: 'ADDomain', location: str = None,
                 password: str = None):
        self.samaccount_name = samaccount_name
        self.domain = domain
        self.domain_dns_name = self.domain.get_domain_dns_name()
        self.realm = self.domain_dns_name.upper()
        self.location = location
        self.password = password

    def get_domain(self) -> 'ADDomain':
        return self.domain

    def get_domain_dns_name(self) -> str:
        return self.domain_dns_name

    def get_samaccount_name(self) -> str:
        return self.samaccount_name


class ManagedADComputer(ManagedADObject):

    def __init__(self, samaccount_name: str, domain: 'ADDomain', location: str = None,
                 password: str = None, service_principal_names: List[str] = None,
                 encryption_types: List[ADEncryptionType] = None, kvno: int = None):
        super().__init__(samaccount_name, domain, location, password)
        self.computer_name = self.samaccount_name[:-1]
        self.name = self.computer_name
        self.service_principal_names = service_principal_names if service_principal_names else []
        self.encryption_types = []
        encryption_types = encryption_types if encryption_types else []
        for enc_type in encryption_types:
            original = enc_type
            if isinstance(enc_type, str):
                enc_type = ENCRYPTION_TYPE_STR_TO_ENUM.get(enc_type.lower())
            if not isinstance(enc_type, ADEncryptionType):
                raise ValueError('All specified encryption types must be ADEncryptionType enums or must '
                                 'be strings convertible to ADEncryptionType enums. {} is neither.'
                                 .format(original))
            self.encryption_types.append(enc_type)
        # assume the account is a new account unless given a kvno
        self.kvno = 1 if kvno is None else kvno

        self.kerberos_keys = []
        self.raw_kerberos_keys = []
        self.server_kerberos_keys = []
        self.user_kerberos_keys = []
        if self.password:
            logger.debug('Generating kerberos keys from password during instantiation of computer with name %s',
                         self.computer_name)
            for enc_type in self.encryption_types:
                raw_key = ad_password_string_to_key(enc_type, self.computer_name,
                                                    self.password, self.domain_dns_name)
                self.raw_kerberos_keys.append(raw_key)

                for spn in self.service_principal_names:
                    server_gss_kerberos_key = GssKerberosKey(spn, self.realm, raw_key, self.kvno,
                                                             gss_name_type=AD_DEFAULT_NAME_TYPE)
                    self.kerberos_keys.append(server_gss_kerberos_key)
                    self.server_kerberos_keys.append(server_gss_kerberos_key)
                # generate our user kerberos key
                user_gss_kerberos_key = GssKerberosKey(self.samaccount_name, self.realm, raw_key, self.kvno,
                                                       gss_name_type=AD_DEFAULT_NAME_TYPE)
                self.kerberos_keys.append(user_gss_kerberos_key)
                self.user_kerberos_keys.append(user_gss_kerberos_key)
            logger.debug('Generated %s kerberos keys from password during instantiation of computer with name %s',
                         len(self.kerberos_keys), self.computer_name)

    def add_encryption_type_locally(self, encryption_type: ADEncryptionType):
        """ Adds an encryption type to the computer locally. This will generate new kerberos keys
        for the computer as a user and for all of the computer's service principal names using the
        new encryption type.
        This function does nothing if the encryption type is already on the computer.
        This function raises an exception if the computer's password is not set, as the password is
        needed to generate new kerberos keys.
        :param encryption_type: The encryption type to add to the computer.
        """
        if encryption_type in self.encryption_types:
            logger.debug(
                'No change resulted from adding encryption type %s to computer %s locally as it was already present',
                encryption_type, self.computer_name)
            return
        if self.password is None:
            raise InvalidComputerParameterException('Encryption types can only be added to a computer locally if its '
                                                    'password is known. Without the password, new kerberos keys cannot '
                                                    'be generated.')
        logger.debug('Adding encryption type %s to computer %s locally',
                     encryption_type, self.computer_name)
        self.encryption_types.append(encryption_type)
        raw_krb_key = ad_password_string_to_key(encryption_type, self.computer_name,
                                                self.password, self.domain_dns_name)
        self.raw_kerberos_keys.append(raw_krb_key)
        for spn in self.service_principal_names:
            server_gss_kerberos_key = GssKerberosKey(spn, self.realm, raw_krb_key, self.kvno,
                                                     gss_name_type=AD_DEFAULT_NAME_TYPE)
            self.kerberos_keys.append(server_gss_kerberos_key)
            self.server_kerberos_keys.append(server_gss_kerberos_key)
        user_gss_kerberos_key = GssKerberosKey(self.samaccount_name, self.realm, raw_krb_key, self.kvno,
                                               gss_name_type=AD_DEFAULT_NAME_TYPE)
        self.kerberos_keys.append(user_gss_kerberos_key)
        self.user_kerberos_keys.append(user_gss_kerberos_key)

    def add_service_principal_name_locally(self, service_principal_name: str):
        """ Adds a service principal name to the computer locally. This will generate new kerberos keys
        for the computer to use to accept security contexts for the service principal name using
        all raw kerberos keys that the account has (and therefore all encryption types it has).
        This function does nothing if the service principal name is already on the computer.

        :param service_principal_name: The service principal name to add to the computer.
        """
        if service_principal_name in self.service_principal_names:
            logger.debug(
                'No change resulted from adding service principal name %s as it was already present for computer %s',
                service_principal_name, self.computer_name)
            return
        logger.debug('Adding service principal name %s to computer %s locally',
                     service_principal_name, self.computer_name)
        self.service_principal_names.append(service_principal_name)
        for raw_krb_key in self.raw_kerberos_keys:
            gss_kerberos_key = GssKerberosKey(service_principal_name, self.realm, raw_krb_key, self.kvno,
                                              gss_name_type=AD_DEFAULT_NAME_TYPE)
            self.kerberos_keys.append(gss_kerberos_key)
            self.server_kerberos_keys.append(gss_kerberos_key)

    def get_full_keytab_file_bytes_for_computer(self) -> bytes:
        """ Get the raw bytes that would comprise a complete keytab file for this computer. The
        resultant bytes form a file that can be used to either accept GSS security contexts as a
        server for any protocol and hostname combinations defined in the service principal names,
        or initiate them as the computer with the computer's user principal name being the
        sAMAccountName.
        """
        return write_gss_kerberos_key_list_to_raw_bytes(self.kerberos_keys)

    def get_server_keytab_file_bytes_for_computer(self) -> bytes:
        """ Get the raw bytes that would comprise a server keytab file for this computer. The resultant
        bytes form a file that can be used to accept GSS security contexts as a server for any protocol
        and hostname combinations defined in the service principal names.
        """
        return write_gss_kerberos_key_list_to_raw_bytes(self.server_kerberos_keys)

    def get_user_keytab_file_bytes_for_computer(self) -> bytes:
        """ Get the raw bytes that would comprise a server keytab file for this computer. The
        resultant bytes form a file that can be used to initiate GSS security contexts as the
        computer with the computer's user principal name being the sAMAccountName.
        """
        return write_gss_kerberos_key_list_to_raw_bytes(self.user_kerberos_keys)

    def get_computer_name(self) -> str:
        return self.computer_name

    def get_computer_distinguished_name(self) -> str:
        """ Get the LDAP distinguished name for the computer. This raises an exception if location is not
        set for the computer.
        """
        if self.location is None:
            raise InvalidComputerParameterException('The location of the computer is unknown and so a distinguished '
                                                    'name cannot be determined for it.')
        return construct_object_distinguished_name(self.computer_name, self.location, self.domain_dns_name)

    def get_encryption_types(self) -> List[ADEncryptionType]:
        return self.encryption_types

    def get_name(self) -> str:
        return self.name

    def get_server_kerberos_keys(self) -> List[GssKerberosKey]:
        return self.server_kerberos_keys

    def get_service_principal_names(self) -> List[str]:
        return self.service_principal_names

    def get_user_kerberos_keys(self) -> List[GssKerberosKey]:
        return self.user_kerberos_keys

    def get_user_principal_name(self) -> str:
        """ Gets the user principal name for the computer, to be used in initiating GSS security contexts """
        return '{sam}@{realm}'.format(sam=self.samaccount_name, realm=self.realm)

    def set_encryption_types_locally(self, encryption_types: List[ADEncryptionType]):
        """ Sets the encryption types of the computer locally. This will generate new kerberos keys
        for the computer as a user and for all of the computer's service principal names using the
        new encryption type.
        This function raises an exception if the computer's password is not set, as the password is
        needed to generate new kerberos keys.
        :param encryption_types: The list of AD encryption types to set on the computer.
        """
        if self.password is None:
            raise InvalidComputerParameterException('Encryption types can only be set on a computer locally if its '
                                                    'password is known. Without the password, new kerberos keys cannot '
                                                    'be generated.')

        new_kerberos_keys = []
        new_raw_kerberos_keys = []
        new_server_kerberos_keys = []
        new_user_kerberos_keys = []
        logger.debug('Adding new encryption types %s to computer %s locally',
                     encryption_types, self.computer_name)
        for encryption_type in encryption_types:
            raw_krb_key = ad_password_string_to_key(encryption_type, self.computer_name,
                                                    self.password, self.domain_dns_name)
            new_raw_kerberos_keys.append(raw_krb_key)
            for spn in self.service_principal_names:
                server_gss_kerberos_key = GssKerberosKey(spn, self.realm, raw_krb_key, self.kvno,
                                                         gss_name_type=AD_DEFAULT_NAME_TYPE)
                new_kerberos_keys.append(server_gss_kerberos_key)
                new_server_kerberos_keys.append(server_gss_kerberos_key)
            user_gss_kerberos_key = GssKerberosKey(self.samaccount_name, self.realm, raw_krb_key, self.kvno,
                                                   gss_name_type=AD_DEFAULT_NAME_TYPE)
            new_kerberos_keys.append(user_gss_kerberos_key)
            new_user_kerberos_keys.append(user_gss_kerberos_key)
        self.encryption_types = encryption_types
        self.kerberos_keys = new_kerberos_keys
        self.raw_kerberos_keys = new_raw_kerberos_keys
        self.server_kerberos_keys = new_server_kerberos_keys
        self.user_kerberos_keys = new_user_kerberos_keys
        logger.debug('Generated %s new kerberos keys for new encryption types %s set on computer %s locally',
                     len(new_kerberos_keys), encryption_types, self.computer_name)

    def set_password_locally(self, password: str):
        """ Sets the password on the AD computer locally. This will regenerate server and user kerberos
        keys for all of the encryption types on the computer.
        This function is meant to be used when the password was not set locally or was incorrectly set.
        This function WILL NOT update the key version number of the kerberos keys; if a computer's
        password is actually changed, then update_password_locally should be used as that will update
        the key version number properly and ensure the resultant kerberos keys can be properly used
        for initiating and accepting security contexts.
        :param password: The string password to set for the computer.
        """
        self.password = password
        self.kerberos_keys = []
        self.raw_kerberos_keys = []
        self.server_kerberos_keys = []
        self.user_kerberos_keys = []
        logger.debug('Generating new kerberos keys for computer %s based on new password',
                     self.computer_name)
        for enc_type in self.encryption_types:
            raw_key = ad_password_string_to_key(enc_type, self.computer_name,
                                                self.password, self.domain_dns_name)
            self.raw_kerberos_keys.append(raw_key)

            for spn in self.service_principal_names:
                server_gss_kerberos_key = GssKerberosKey(spn, self.realm, raw_key, self.kvno,
                                                         gss_name_type=AD_DEFAULT_NAME_TYPE)
                self.kerberos_keys.append(server_gss_kerberos_key)
                self.server_kerberos_keys.append(server_gss_kerberos_key)
            # generate our user kerberos key
            user_gss_kerberos_key = GssKerberosKey(self.samaccount_name, self.realm, raw_key, self.kvno,
                                                   gss_name_type=AD_DEFAULT_NAME_TYPE)
            self.kerberos_keys.append(user_gss_kerberos_key)
            self.user_kerberos_keys.append(user_gss_kerberos_key)
        logger.info('Generated %s new kerberos keys for computer %s based on new password and forgot old keys',
                    len(self.kerberos_keys), self.computer_name)

    def set_service_principal_names_locally(self, service_principal_names: List[str]):
        """ Sets the service principal names for the computer, and regenerates new server kerberos keys
        for all of the newly set service principal names.
        :param service_principal_names: A list of string service principal names to set for the computer.
        """
        logger.debug('Generating new kerberos keys for service principal names %s set on computer %s',
                     service_principal_names, self.computer_name)
        new_kerberos_keys = []
        for spn in self.service_principal_names:
            for raw_krb_key in self.raw_kerberos_keys:
                gss_kerberos_key = GssKerberosKey(spn, self.realm, raw_krb_key, self.kvno,
                                                  gss_name_type=AD_DEFAULT_NAME_TYPE)
                new_kerberos_keys.append(gss_kerberos_key)
        self.service_principal_names = service_principal_names
        self.kerberos_keys = new_kerberos_keys + self.user_kerberos_keys
        logger.debug('Generated %s new kerberos keys for new service principal names %s set on computer %s locally',
                     len(new_kerberos_keys), service_principal_names, self.computer_name)

    def write_full_keytab_file_for_computer(self, file_path: str, merge_with_existing_file: bool = True):
        """ Write all of the keytabs for this computer to a file, regardless of whether they represent keys for
        the computer to authenticate with other servers as a client, or keys to authenticate clients when acting
        as a server.

        :param file_path: The path to the file where the keytabs will be written. If it does not exist, it will be
                          created.
        :param merge_with_existing_file: If True, the computers keytabs will be added into the keytab file at
                                         `file_path` if one exists. If False, the file at `file_path` will be
                                         overwritten if it exists. If the file does not exist, this does nothing.
                                         Defaults to True.
        """
        logger.debug('Writing full key file for computer %s to %s', self.computer_name, file_path)
        entries_to_write = self.kerberos_keys
        if merge_with_existing_file:
            logger.debug('Merging with existing keytab file')
            current_entries = process_keytab_file_to_extract_entries(file_path, must_exist=False)
            logger.debug('%s existing keytabs found in file %s for merge', len(current_entries), file_path)
            entries_to_write += current_entries
        data = write_gss_kerberos_key_list_to_raw_bytes(entries_to_write)
        self._write_keytab_data(file_path, data)
        logger.info('Successfully wrote full key file with %s keys for computer %s to %s',
                    len(self.kerberos_keys), self.computer_name, file_path)

    def write_server_keytab_file_for_computer(self, file_path: str, merge_with_existing_file: bool = True):
        """ Write all of the server keytabs for this computer to a file, which are the keys used to authenticate
        clients when acting as a server.

        :param file_path: The path to the file where the keytabs will be written. If it does not exist, it will be
                          created.
        :param merge_with_existing_file: If True, the computers keytabs will be added into the keytab file at
                                         `file_path` if one exists. If False, the file at `file_path` will be
                                         overwritten if it exists. If the file does not exist, this does nothing.
                                         Defaults to True.
        """
        logger.debug('Writing server key file for computer %s to %s', self.computer_name, file_path)
        entries_to_write = self.server_kerberos_keys
        if merge_with_existing_file:
            logger.debug('Merging with existing keytab file')
            current_entries = process_keytab_file_to_extract_entries(file_path, must_exist=False)
            logger.debug('%s existing keytabs found in file %s for merge', len(current_entries), file_path)
            entries_to_write += current_entries
        data = write_gss_kerberos_key_list_to_raw_bytes(entries_to_write)
        self._write_keytab_data(file_path, data)
        logger.info('Successfully wrote server key file with %s keys for computer %s to %s',
                    len(self.server_kerberos_keys), self.computer_name, file_path)

    def write_user_keytab_file_for_computer(self, file_path: str, merge_with_existing_file: bool = True):
        """ Write all of the user keytabs for this computer to a file, which are the keys used to authenticate
        with other servers when acting as a client.

        :param file_path: The path to the file where the keytabs will be written. If it does not exist, it will be
                          created.
        :param merge_with_existing_file: If True, the computers keytabs will be added into the keytab file at
                                         `file_path` if one exists. If False, the file at `file_path` will be
                                         overwritten if it exists. If the file does not exist, this does nothing.
                                         Defaults to True.
        """
        logger.debug('Writing user key file for computer %s to %s', self.computer_name, file_path)
        entries_to_write = self.user_kerberos_keys
        if merge_with_existing_file:
            logger.debug('Merging with existing keytab file')
            current_entries = process_keytab_file_to_extract_entries(file_path, must_exist=False)
            logger.debug('%s existing keytabs found in file %s for merge', len(current_entries), file_path)
            entries_to_write += current_entries
        data = write_gss_kerberos_key_list_to_raw_bytes(entries_to_write)
        self._write_keytab_data(file_path, data)
        logger.info('Successfully wrote user key file with %s keys for computer %s to %s',
                    len(self.user_kerberos_keys), self.computer_name, file_path)

    def _write_keytab_data(self, file_path: str, data: bytes):
        with open(file_path, 'wb') as fp:
            fp.write(data)

    def update_password_locally(self, password: str):
        """ Update the password for the computer locally and generate new kerberos keys for the new
        password.
        :param password: The string password to set for the computer.
        """
        self.kvno += 1
        logger.debug('Updated kvno for computer %s from %s to %s', self.computer_name, self.kvno - 1, self.kvno)
        self.set_password_locally(password)
