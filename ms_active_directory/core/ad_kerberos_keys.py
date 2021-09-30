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

from typing import Union

from ms_active_directory import logging_utils

from ms_active_directory.environment.kerberos.kerberos_constants import (
    AD_ENC_TYPE_TO_KRB5_ENC_TYPE_MAP,
    DEFAULT_UNKNOWN_NAME_TYPE,
    KRB5_ENC_TYPE_TO_AD_ENC_TYPE_MAP,
    NAME_TYPE_VALUE_TO_NAME_TYPE_MAP,
    PREFERRED_KEYTAB_FORMAT_VERSION
)
from ms_active_directory.environment.kerberos.kerberos_keytab_generator import write_complete_keytab_structure_to_raw_bytes
from ms_active_directory.environment.security.security_config_constants import (
    ADEncryptionType
)


logger = logging_utils.get_logger()


class RawKerberosKey:
    """ A raw kerberos key - containing only the generated shared secret and the encryption type.
    This does not contain any information about who's using it, its purpose, etc. and is tied
    only to the password used, the salt, and the encryption type. It can therefore be used to
    generate usable kerberos keys for either accepting or initiating GSS authentication.
    """
    def __init__(self, enc_type: Union[ADEncryptionType, str], key_bytes: bytes):
        # leave enc_type flexible. it can be either an ADEncryption type or a string depending on whether
        # we generate this key ourselves for an AD account or read it in from a keytab file
        self.encryption_type = enc_type
        self.key_bytes = key_bytes
        # hex is the most common key representation for visual display, so we have it by default
        self.raw_hex_encoded_key = key_bytes.hex()
        self.hex_encoded_key = '0x' + self.raw_hex_encoded_key

    def get_key_bytes(self):
        return self.key_bytes

    def get_hex_encoded_key(self):
        return self.hex_encoded_key

    def get_raw_hex_encoded_key(self):
        return self.raw_hex_encoded_key

    def uses_active_directory_supported_encryption_type(self):
        return (isinstance(self.encryption_type, ADEncryptionType)
                or self.encryption_type in KRB5_ENC_TYPE_TO_AD_ENC_TYPE_MAP)


class GssKerberosKey:
    """ A kerberos key that can actually be used in kerberos negotiation (as either a user or a server).
    This is a raw key properly wrapped with encoded additional information about the principal, kvno,
    encryption type, etc.
    """

    def __init__(self, principal: str, realm: str, raw_key: RawKerberosKey, kvno: int, flags: int = None,
                 timestamp: int = None, gss_name_type: int = DEFAULT_UNKNOWN_NAME_TYPE,
                 format_version: int = PREFERRED_KEYTAB_FORMAT_VERSION):
        self.principal = principal
        self.realm = realm
        self.raw_key = raw_key
        # technically, for AD-only purposes, we could have typed this as an ADEncryptionType.
        # but since this is built directly from a keytab file in some cases, we might have
        # read in something else
        enc_type = self.raw_key.encryption_type
        if isinstance(enc_type, ADEncryptionType):
            enc_type = AD_ENC_TYPE_TO_KRB5_ENC_TYPE_MAP[enc_type]
        self.encryption_type = enc_type
        self.kvno = kvno
        self.flags = flags
        self.timestamp = timestamp
        self.gss_name_type = gss_name_type
        self.friendly_gss_name_type = None
        # allow for unrecognized gss name type values just in case something new comes out.
        # this field is flavor text anyway and doesn't require functional support, so any
        # value that actually works with the kerberos protocol is fine to use even if we
        # don't have a friendly name for it
        if self.gss_name_type in NAME_TYPE_VALUE_TO_NAME_TYPE_MAP:
            self.friendly_gss_name_type = NAME_TYPE_VALUE_TO_NAME_TYPE_MAP[gss_name_type]
        self.format_version = format_version
        self.complete_keytab_bytes = None

    def get_complete_keytab_bytes(self, format_version: int = None, use_current_time: bool = None):
        """ Get this key object encoded as the bytes of a complete, usable keytab that can be written
        to a file and used for kerberos authentication (initiating or accepting contexts).
        :param format_version: An keytab format version. If not specified, defaults to the format version
                               in the object. If the object's format version is null, defaults to 2.
        :param use_current_time: Whether or not the current time should be used as the timestamp in the
                                 keytab produced, overwriting the time in the object. If no timestamp is
                                 in the object, the current time is used. Defaults to False if not specified.
        """
        return write_complete_keytab_structure_to_raw_bytes(self, keytab_format_version=format_version,
                                                            use_current_time_for_keytab=use_current_time)

    def get_raw_key_bytes(self):
        return self.raw_key.get_key_bytes()

    def uses_active_directory_supported_encryption_type(self):
        return self.encryption_type in KRB5_ENC_TYPE_TO_AD_ENC_TYPE_MAP

    def set_principal(self, principal: str):
        """ Sets the principal and clears complete_gss_keytab_bytes so we re-compute it """
        self.principal = principal
        self.complete_keytab_bytes = None

    def set_realm(self, realm: str):
        """ Sets the realm and clears complete_gss_keytab_bytes so we re-compute it """
        self.realm = realm
        self.complete_keytab_bytes = None

    def set_raw_key(self, raw_key: RawKerberosKey):
        """ Sets the raw key, updates our encryption type and clears complete_gss_keytab_bytes so we re-compute it.
        The encryption type is directly tied to our raw key and vice versa, so setting one without the other makes no
        sense.
        """
        self.raw_key = raw_key
        enc_type = self.raw_key.encryption_type
        if isinstance(enc_type, ADEncryptionType):
            enc_type = AD_ENC_TYPE_TO_KRB5_ENC_TYPE_MAP[enc_type]
        self.encryption_type = enc_type
        self.complete_keytab_bytes = None

    def set_kvno(self, kvno: int):
        """ Sets the kvno and clears complete_gss_keytab_bytes so we re-compute it """
        self.kvno = kvno
        self.complete_keytab_bytes = None

    def set_flags(self, flags: int):
        """ Sets the flags and clears complete_gss_keytab_bytes so we re-compute it """
        self.flags = flags
        self.complete_keytab_bytes = None

    def set_timestamp(self, timestamp: int):
        """ Sets the timestamp and clears complete_gss_keytab_bytes so we re-compute it """
        self.timestamp = timestamp
        self.complete_keytab_bytes = None

    def set_gss_name_type(self, name_type: int):
        """ Sets the gss name type and friendly name type and clears complete_gss_keytab_bytes so we re-compute it """
        self.gss_name_type = name_type
        self.friendly_gss_name_type = NAME_TYPE_VALUE_TO_NAME_TYPE_MAP[name_type]
        self.complete_keytab_bytes = None

    def set_format_version(self, format_version: int):
        """ Sets the keytab format version and clears complete_gss_keytab_bytes so we re-compute it """
        self.format_version = format_version
        self.complete_keytab_bytes = None
