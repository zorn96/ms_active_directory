""" Utilities for constructing keytabs data using the attributes of a GssKerberosKey and combining keytabs.

See this page for more info on the evolution of the format beyond the code comments explaining how things work
conceptually: http://manpages.ubuntu.com/manpages/artful/man3/krb5_fileformats.3.html
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

import binascii
import math
import time

from typing import List, TYPE_CHECKING

if TYPE_CHECKING:
    from ms_active_directory.core.ad_kerberos_keys import GssKerberosKey, RawKerberosKey

from ms_active_directory import logging_utils

from ms_active_directory.environment.kerberos.kerberos_constants import (
    DEFAULT_UNKNOWN_NAME_TYPE,
    ENCRYPTION_TYPE_FIELD_SIZE,
    ENTRY_LENGTH_FIELD_SIZE_BYTES,
    FLAGS_FIELD_SIZE_BYTES,
    KEYTAB_FORMAT_SIZE_BYTES,
    KEYTAB_FORMAT_VERSION_FOR_KEYTAB_FORMAT_VERSION,
    KEY_LENGTH_FIELD_SIZE_BYTES,
    KRB5_ENC_TYPE_TO_ENC_TYPE_VALUE_MAP,
    LEADING_HEX_FOR_KERBEROS_V5,
    NUM_COMPONENTS_FIELD_SIZE_BYTES,
    REALM_LENGTH_FIELD_SIZE_BYTES,
    PREFERRED_KEYTAB_FORMAT_VERSION,
    PRINCIPAL_COMPONENT_DIVIDER,
    PRINCIPAL_COMPONENT_LENGTH_FIELD_SIZE_BYTES,
    PRINCIPAL_TYPE_FIELD_SIZE_BYTES,
    TIMESTAMP_FIELD_SIZE_BYTES,
    VNO8_FIELD_SIZE_BYTES,
    VNO32_FIELD_SIZE_BYTES,
)
from ms_active_directory.exceptions import KeytabEncodingException

logger = logging_utils.get_logger()


def write_gss_kerberos_key_list_to_raw_bytes(gss_key_list: List['GssKerberosKey'],
                                             keytab_format_version: int = None) -> bytes:
    """ Given a list of fully formed keytab dictionaries, convert them to bytes representing all of them as a single
    keytab.
    This just builds upon the function to convert keytabs to hex, and then transforms the hex to bytes.
    """
    hex_data = write_gss_kerberos_key_list_to_raw_hex(gss_key_list, keytab_format_version)
    return binascii.unhexlify(hex_data)


def write_gss_kerberos_key_list_to_raw_hex(gss_key_list: List['GssKerberosKey'],
                                           keytab_format_version: int = None) -> str:
    """ Given a list of GssKerberosKey objects, convert them to a hex string representing all of them as a
    single kerberos keytab, usable for standard GSS authentication (either initiating or receiving).
    Optionally, a format version may be specified. If a format version is not provided, then all keytabs will be
    written in the format of the first keytab provided. If the first keytab provided does not have a format version
    then we will default to our preferred keytab format version.

    :returns: A hex-encoded string representing the data of a fully-formed keytab file, with no leading 0x in order
              to allow for easier writing out to a file/translation to bytes.
    """
    # if we have no keys just return
    if len(gss_key_list) == 0:
        return ''

    leading_keytab = gss_key_list.pop(0)
    # if no keytab format version is specified, assume that all of them should be written in the same format as the
    # first one
    if keytab_format_version is None:
        keytab_format_version = leading_keytab.format_version
    if keytab_format_version is None:
        keytab_format_version = PREFERRED_KEYTAB_FORMAT_VERSION

    kt_hex_string = write_complete_keytab_structure_to_raw_hex_data(leading_keytab,
                                                                    keytab_format_version=keytab_format_version)
    # process remaining keys (if any)
    for keytab_dict in gss_key_list:
        kt_hex_string += write_complete_keytab_structure_to_raw_hex_data(keytab_dict,
                                                                         keytab_format_version=keytab_format_version,
                                                                         include_keytab_format_prefix=False)
    return kt_hex_string


def write_complete_keytab_structure_to_raw_bytes(gss_key: 'GssKerberosKey', keytab_format_version: int = None,
                                                 include_keytab_format_prefix: bool = True,
                                                 use_current_time_for_keytab: bool = False) -> bytes:
    """ This is just a wrapper around write_complete_keytab_structure_to_raw_hex_data - go read its docstring
    This takes the result of write_complete_keytab_structure_to_raw_hex_data and encodes it to bytes before
    returning.
    """
    hex_data = write_complete_keytab_structure_to_raw_hex_data(gss_key, keytab_format_version,
                                                               include_keytab_format_prefix,
                                                               use_current_time_for_keytab)
    return binascii.unhexlify(hex_data)


def write_complete_keytab_structure_to_raw_hex_data(gss_key: 'GssKerberosKey', keytab_format_version: int = None,
                                                    include_keytab_format_prefix: bool = True,
                                                    use_current_time_for_keytab: bool = False) -> str:
    """ This function, given a GssKerberosKey, will write it to bytes.
    Optionally, it can be forced into a specific keytab format version. If that isn't specified, then it will be
    written in the format version in the GssKerberosKey object.
    Optionally, the keytab format prefix and leading byte to indicate kerberos version 5 can be excluded. This is
    particularly useful if you plan to combine the result of this with other keytabs in a merge. But by default the
    byte is included, so the return value is a valid standalone keytab that can be used for authentication without
    additional processing.

    This function is essentially the behavior of the kerberos_keytab_ingesterr.py file in reverse.
    :param gss_key: The GssKerberosKey to turn into keytab data
    :param keytab_format_version: The format version to use for encoding numbers in the keytab
    :param include_keytab_format_prefix: If true, the leading 0x5 byte is included, along with the keytab format version
                                         written to a number, at the start of the keytab. This makes it ready for use
                                         in authentication.
    :param use_current_time_for_keytab: If true, overwrite the timestamp in the gss_key with the current time. This is
                                        the behavior of many command line kerberos tools like ktutil. If false, the
                                        timestamp is preserved. If no timestamp exists for the gss_key, then the current
                                        time will always be used. Defaults to False because I think the behavior of
                                        ktutil is stupid, and having a keytab's data change whenever I copy it from
                                        one file to another is confusing.
    """
    if keytab_format_version is None:
        keytab_format_version = gss_key.format_version

    keytab_hex_lead = ''

    if include_keytab_format_prefix:
        keytab_hex_lead = LEADING_HEX_FOR_KERBEROS_V5
        keytab_hex_lead += _write_number_to_hex(keytab_format_version,
                                                number_repr_size_in_bytes=KEYTAB_FORMAT_SIZE_BYTES,
                                                keytab_format_version=KEYTAB_FORMAT_VERSION_FOR_KEYTAB_FORMAT_VERSION)

    # track our keytab body separate from the lead so we don't include the lead in entry length analyses
    keytab_hex_body = ''

    # the first thing we'll encode is the number of components. this is recalculated by breaking up the gss_key's
    # principal
    num_components = len(gss_key.principal.split(PRINCIPAL_COMPONENT_DIVIDER))
    # if our keytab format version is 1, then the number of components is supposed to be 1 too large because there
    # was literally a bug in the v1 format in how it accounted for components :(
    if keytab_format_version == 1:
        num_components += 1
    keytab_hex_body += _write_number_to_hex(num_components, number_repr_size_in_bytes=NUM_COMPONENTS_FIELD_SIZE_BYTES,
                                            keytab_format_version=keytab_format_version)

    # next, we write the realm
    keytab_hex_body += _write_realm_to_hex(gss_key.realm, keytab_format_version=keytab_format_version)

    # third we write our principal
    keytab_hex_body += _write_principal_to_hex(gss_key.principal, keytab_format_version=keytab_format_version)

    # the last piece of information about the principal to write is the principal type. this doesn't functionally matter
    # and many KDCs will populate a generic GSS API name type here.
    # However, this information can be helpful for figuring out the intention of the KDC when the keytab was first
    # created. For example, users and servers are different types, so if the manager intended for this to the user
    # keytab OF A SERVER (to let the server query for info about users it's authenticating/authorizing) then this info
    # can help differentiate it from true user keys
    # keytab format version 1 does not include this value
    name_type = gss_key.gss_name_type if gss_key.gss_name_type is not None else DEFAULT_UNKNOWN_NAME_TYPE
    if keytab_format_version != 1:
        keytab_hex_body += _write_number_to_hex(name_type, PRINCIPAL_TYPE_FIELD_SIZE_BYTES,
                                                keytab_format_version=keytab_format_version)

    # the next two things to write are the time of keytab generation and the old 8-bit version of kvno.
    # the 8-bit version is useless everywhere except for old machines (like ubuntu 14 with an older libkrb5) because
    # we'll also encode the 32-bit version which will be preferred
    # the time is just the time the file was generated, and so it changes anytime keytabs are passed through ktutil.
    # this is stupid
    # if the caller indicated to use the current time rather than the time in the gss_key, or if the gss_key has no
    # timestamp, then use the current time
    current_time = int(time.time())
    timestamp = gss_key.timestamp
    if use_current_time_for_keytab or gss_key.timestamp is None:
        timestamp = current_time
    keytab_hex_body += _write_number_to_hex(timestamp, TIMESTAMP_FIELD_SIZE_BYTES,
                                            keytab_format_version=keytab_format_version)

    # according to spec, if our kvno doesn't fit in 8 bits (>255), then we write the lower 8 bits of our kvno for the
    # 8-bit version of kvno. this is ignored in favor of the 32 bit field
    kvno32 = gss_key.kvno
    kvno8 = kvno32
    if kvno32 > 2 ** 8 - 1:
        bit_string = bin(kvno32)
        last_8 = bit_string[-8:]
        kvno8 = int(last_8, 2)
    keytab_hex_body += _write_number_to_hex(kvno8, VNO8_FIELD_SIZE_BYTES,
                                            keytab_format_version=keytab_format_version)

    # next we write the encryption type and the secret key itself.
    # the encryption type tells us how our key was formed and how it should be used as a shared secret. many keys will
    # be the same size, and a good encryption key doesn't betray what encryption scheme was used to create it by its
    # appearance, so we encode encryption type so that we can understand how to encrypt/sign/decrypt data
    # our key is the only part of the keytab entry that ACTUALLY matters cryptographically for authentication, signing,
    # and sealing with kerberos.
    # encryption type comes first
    enc_type = gss_key.encryption_type
    enc_type_value = KRB5_ENC_TYPE_TO_ENC_TYPE_VALUE_MAP.get(enc_type)
    keytab_hex_body += _write_number_to_hex(enc_type_value, ENCRYPTION_TYPE_FIELD_SIZE,
                                            keytab_format_version=keytab_format_version)
    keytab_hex_body += _write_raw_kerberos_key_to_keytab_entry(gss_key.raw_key,
                                                               keytab_format_version=keytab_format_version)

    # now write the 32-bit version of our key version number
    keytab_hex_body += _write_number_to_hex(kvno32, VNO32_FIELD_SIZE_BYTES, keytab_format_version=keytab_format_version)

    # flags are optional. only encode them if they're non-null
    flags = gss_key.flags
    if flags is not None:  # flags could be 0 as it's numeric
        keytab_hex_body += _write_number_to_hex(flags, FLAGS_FIELD_SIZE_BYTES,
                                                keytab_format_version=keytab_format_version)

    # so calculate the size of the entry now that we've encoded all of the data and prepend it
    entry_length = len(keytab_hex_body)
    # 2 hex digits = 1 byte, so our byte length is half our string length since we used hex
    entry_length_bytes = entry_length // 2
    entry_length_field = _write_number_to_hex(entry_length_bytes,
                                              number_repr_size_in_bytes=ENTRY_LENGTH_FIELD_SIZE_BYTES,
                                              keytab_format_version=keytab_format_version)
    keytab_hex_body = entry_length_field + keytab_hex_body

    return keytab_hex_lead + keytab_hex_body


def _write_number_to_hex(number_to_write: int, number_repr_size_in_bytes: int, keytab_format_version: int) -> str:
    """ Write any number to hex, while allocating the number of bytes specified.
    Number fields in a keytab occupy a fixed size, so we make sure to account for that when encoding them to hex.
    """
    byte_order = 'little'
    if keytab_format_version == 2:
        byte_order = 'big'
    elif keytab_format_version != 1:
        raise KeytabEncodingException('Invalid keytab format version {}. Format version must be 1 or 2'
                                      .format(keytab_format_version))
    # this raises an exception if the number to write is too big to fit in number_repr_size_in_bytes
    return number_to_write.to_bytes(number_repr_size_in_bytes, byte_order).hex()


def _write_string_to_hex(string_to_write: str) -> str:
    """ Write any string to hex.
    As mentioned above, numbers get padded because all numbers are a fixed size in keytabs.
    However, strings are super free-form, like principals and realms. They're not constrained to a fixed size ever, and
    so instead all string fields will also end up encoding their length before them in the keytab. So there's no need
    for any input other than the string itself to this function.
    """
    return string_to_write.encode().hex()


def _write_string_and_its_length_to_hex(any_string: str, size_of_length_field_bytes: int,
                                        keytab_format_version: int) -> str:
    """ Write any string, and the information needed to read it back from a keytab, to hex.
    This is done backwards - all strings are. We convert the string value to hex, then measure it's length after.
    Then we combine those in reverse - in the style 'string length hex | string hex' and return that so that when
    reading the keytab forwards, the length of the string precedes it.
    The size used to encode the length of the string must also be specified, as different string fields encode their
    length using differently sized integers. Why? Who knows!
    """
    # 1 character = 1 byte so this is easy
    str_byte_length = len(any_string)
    str_length_hex = _write_number_to_hex(str_byte_length, size_of_length_field_bytes, keytab_format_version)
    return str_length_hex + _write_string_to_hex(any_string)


def _write_realm_to_hex(realm: str, keytab_format_version: int) -> str:
    """ Write our realm to hex. """
    return _write_string_and_its_length_to_hex(realm, REALM_LENGTH_FIELD_SIZE_BYTES, keytab_format_version)


def _write_principal_component_to_hex(component: str, keytab_format_version: int) -> str:
    """ Write a principal component to hex. """
    return _write_string_and_its_length_to_hex(component, PRINCIPAL_COMPONENT_LENGTH_FIELD_SIZE_BYTES,
                                               keytab_format_version)


def _write_principal_to_hex(principal: str, keytab_format_version: int) -> str:
    """ Write a kerberos principal to hex.
    This means splitting up the components of the principal, the converting the components to hex, measuring each
    component's length in bytes and encoding that length, then concatenating them all and returning.
    """
    spn_components = principal.split(PRINCIPAL_COMPONENT_DIVIDER)
    final_hex = ''
    for component in spn_components:
        final_hex += _write_principal_component_to_hex(component, keytab_format_version)
    return final_hex


def _write_raw_kerberos_key_to_keytab_entry(raw_key: 'RawKerberosKey', keytab_format_version: int) -> str:
    """ Prep our raw kerberos key for inclusion in a keytab entry.
    We can extract the hex from a RawKerberosKey object natively, so we just need to measure its length and then
    add that in front before returning so it can be read back like any other string.
    """
    hex_encoded_key = raw_key.get_raw_hex_encoded_key()
    # 1 hex digit = 4 bits, 1 byte = 8 bits, so to measure the byte length of a hex string we halve its length.
    # keys are always even numbers in length, but just in case, round up non-integers
    key_byte_length = len(hex_encoded_key) / 2
    if key_byte_length != int(key_byte_length):
        key_byte_length = math.ceil(key_byte_length)
    key_byte_length = int(key_byte_length)  # cast back to int
    key_length_hex = _write_number_to_hex(key_byte_length, KEY_LENGTH_FIELD_SIZE_BYTES, keytab_format_version)
    return key_length_hex + hex_encoded_key
