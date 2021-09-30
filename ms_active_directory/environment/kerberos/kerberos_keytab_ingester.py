""" Utilities for parsing keytab files into GSS Kerberos Keys. """
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
import os

from typing import List, Tuple

from ms_active_directory import logging_utils

from ms_active_directory.core.ad_kerberos_keys import GssKerberosKey, RawKerberosKey
# constants for structuring in-memory keytab representations
from ms_active_directory.environment.kerberos.kerberos_constants import (
    KEYTAB_FORMAT_VERSION_FOR_KEYTAB_FORMAT_VERSION,
    KRB5_ENC_TYPE_VALUE_TO_ENC_TYPE_MAP,
)

# constants for parsing keytab data, as a separate import for improved readability
from ms_active_directory.environment.kerberos.kerberos_constants import (
    ENCRYPTION_TYPE_FIELD_SIZE,
    ENTRY_LENGTH_FIELD_SIZE_BYTES,
    FLAGS_FIELD_SIZE_BYTES,
    KEYTAB_STANDARD_LEADING_BYTES_SIZE,
    KEYTAB_FORMAT_SIZE_BYTES,
    KEY_LENGTH_FIELD_SIZE_BYTES,
    NUM_COMPONENTS_FIELD_SIZE_BYTES,
    REALM_LENGTH_FIELD_SIZE_BYTES,
    PRINCIPAL_COMPONENT_DIVIDER,
    PRINCIPAL_COMPONENT_LENGTH_FIELD_SIZE_BYTES,
    PRINCIPAL_TYPE_FIELD_SIZE_BYTES,
    TIMESTAMP_FIELD_SIZE_BYTES,
    VNO8_FIELD_SIZE_BYTES,
    VNO32_FIELD_SIZE_BYTES,
)
from ms_active_directory.exceptions import KeytabEncodingException

logger = logging_utils.get_logger()


def process_keytab_bytes_to_extract_entries(keytab: bytes) -> List[GssKerberosKey]:
    """ Given a byte string of binary keytab data, extract keytab entries from it and return them as GSSKerberosKeys.
    """
    hex_keytab_data = binascii.hexlify(keytab).decode('utf-8')
    return process_hex_string_keytab_file_to_extract_entries(hex_keytab_data)


def process_keytab_file_to_extract_entries(keytab_file_path: str, must_exist: bool = True) -> List[GssKerberosKey]:
    """ Given a file path for a keytab, extract keytab entries from it and return them as GSSKerberosKeys. """
    if not os.path.isfile(keytab_file_path):
        if not must_exist:
            return []
        raise KeytabEncodingException('File {} cannot be found for reading keytabs.'
                                      .format(keytab_file_path))
    keytab_data = open(keytab_file_path, 'rb').read()
    return process_keytab_bytes_to_extract_entries(keytab_data)


def _twos_complement(value: int, bits: int) -> int:
    """ This does twos complement so we can convert hex strings to signed integers.
    Why is this not built-in to python int?
    """
    if value & (1 << (bits - 1)):
        value -= 1 << bits
    return value


def _read_bytes_as_number(keytab: str, index: int, bytes_to_read: int = 1, keytab_format_version: int = 1,
                          is_signed_int: bool = False) -> int:
    """ Given hex-encoded keytab data, the index we're starting from, the number of
    bytes in the keytab we want to read, and the keytab format version, this function
    will read and interpret the bytes requested starting at the index. Bytes may be
    reordered depending on format version, as versions change between big-endian and
    little-endian encoding.
    The resultant hex is them decoded to an integer and returned.

    Format version 1 means native byte order
    Format version 2 means big-endian byte order
    Format pulled from https://www.h5l.org/manual/HEAD/krb5/krb5_fileformats.html

    A hex number is 4 bits, so our "bytes to read" value gets doubled to determine
    actual offsets in our hex string.
    """
    # since our string is hex, a byte is represented by 2 characters, so our string offset to read is twice
    # the number of bytes
    offset = bytes_to_read * 2
    end_index = index + offset
    if end_index > len(keytab):
        return 0

    hex_string_to_parse = keytab[index:end_index]
    if keytab_format_version == 1:
        converted_from_little_endian = []
        for i in range(0, offset, 2):
            converted_from_little_endian.insert(0, hex_string_to_parse[i:i + 2])
        hex_string_to_parse = ''.join(converted_from_little_endian)
    elif keytab_format_version != 2:
        raise KeytabEncodingException('Unrecognized keytab format version {}'.format(keytab_format_version))

    unsigned_value = int(hex_string_to_parse, 16)
    if is_signed_int:
        return _twos_complement(unsigned_value, bytes_to_read * 8)  # 8 bits per byte
    return unsigned_value


def _read_bytes_as_string(keytab: str, index: int, bytes_to_read: int) -> str:
    """ Given hex-encoded keytab data, the index we're starting from, the number of
    bytes in the keytab we want to read, and the keytab format version, this function
    will read and interpret the bytes requested starting at the index.
    The resultant hex is them decoded to a UTF-8 string and returned.

    A hex number is 4 bits, so our "bytes to read" value gets doubled to determine
    actual offsets in our hex string.
    """
    offset = bytes_to_read * 2
    end_index = index + offset
    if end_index > len(keytab):
        return '0'  # this is the same as get_bytes_number above. when we can't read, return 0
    return bytearray.fromhex(keytab[index:end_index]).decode('UTF-8')


def _read_bytes_to_number_and_then_move_position(keytab: str, current_keytab_position: int, bytes_to_read: int,
                                                 keytab_format_version: int,
                                                 is_signed_int: bool = False) -> Tuple[int, int]:
    """ Read some number of bytes from the keytab starting at the given position, move our
    position in the keytab forward, and return the value read as an integer and the new position.

    A hex number is 4 bits, so our "bytes to read" value gets doubled to calculate
    how far to move position in our hex string.
    """
    read_value = _read_bytes_as_number(keytab, index=current_keytab_position, bytes_to_read=bytes_to_read,
                                       keytab_format_version=keytab_format_version, is_signed_int=is_signed_int)
    new_keytab_position = current_keytab_position + 2 * bytes_to_read
    return read_value, new_keytab_position


def _read_bytes_to_string_and_then_move_position(keytab: str, current_keytab_position: int,
                                                 bytes_to_read: int) -> Tuple[str, int]:
    """ Read some number of bytes from the keytab starting at the given position, move our
    position in the keytab forward, and return the value read and the new position.

    A hex number is 4 bits, so our "bytes to read" value gets doubled to calculate
    how far to move position in our hex string.
    """
    read_value = _read_bytes_as_string(keytab, index=current_keytab_position, bytes_to_read=bytes_to_read)
    new_keytab_position = current_keytab_position + 2 * bytes_to_read
    return read_value, new_keytab_position


def _get_principal_component_length_and_then_read_component(keytab: str, current_keytab_position: int,
                                                            keytab_format_version: int) -> Tuple[str, int]:
    """ Extract the component length value from a keytab and then read the following component.
    Component length is always encoded into the keytab in a fixed size entry, so we can always
    read component lengths the same way and interpret them.

    :returns: a tuple of component value, keytab position after reading
    """
    component_length, current_keytab_position = _read_bytes_to_number_and_then_move_position(keytab,
                                                                                             current_keytab_position,
                                                                                             PRINCIPAL_COMPONENT_LENGTH_FIELD_SIZE_BYTES,
                                                                                             keytab_format_version)
    component, current_keytab_position = _read_bytes_to_string_and_then_move_position(keytab, current_keytab_position,
                                                                                      component_length)
    return component, current_keytab_position


def process_hex_string_keytab_file_to_extract_entries(keytab: str) -> List[GssKerberosKey]:
    """ Given a hex encoded keytab file, extract all of the entries in it and return a list of
    dictionaries describing each entry.
    """
    # keytab metadata - figure out our keytab format version and make sure it's valid
    current_keytab_position = 0
    start_byte = _read_bytes_as_number(keytab, bytes_to_read=KEYTAB_STANDARD_LEADING_BYTES_SIZE,
                                       index=current_keytab_position)
    if start_byte != 5:
        raise KeytabEncodingException('Keytabs must always start with 0x05 as the leading byte, as only Kerberos v5 '
                                      'keytabs are supported. Seen leading byte: {}'.format(start_byte))
    # one byte is 2 hex digits, so move positions equal to 2x our size in bytes
    current_keytab_position += 2 * KEYTAB_STANDARD_LEADING_BYTES_SIZE

    # we check our format version by reading bytes in the default v1 format, because that's how
    # backwards compatibility works. the thing that tells you "you're in the new format" is
    # written in the old format, so that everyone can read it.
    keytab_format_version = _read_bytes_as_number(keytab, bytes_to_read=KEYTAB_FORMAT_SIZE_BYTES,
                                                  keytab_format_version=KEYTAB_FORMAT_VERSION_FOR_KEYTAB_FORMAT_VERSION,
                                                  index=current_keytab_position)
    if keytab_format_version != 1 and keytab_format_version != 2:
        raise KeytabEncodingException('Unrecognized and unsupported keytab format version: {}'
                                      .format(keytab_format_version))
    logger.debug('Ingesting keytab with format version %s', keytab_format_version)
    # one byte is 2 hex digits, so move positions equal to 2x our size in bytes
    current_keytab_position += 2 * KEYTAB_FORMAT_SIZE_BYTES

    # this is the prefix the encodes our keytab format version. it only appears once for the entire
    # file. so if we want to split up our file into all of its individual entries, we want to prepend
    # the contents of each entry with this standalone prefix so that they can be utilized as file
    # data without extra processing
    standalone_prefix = keytab[:current_keytab_position]
    entries = []
    # int32_t size of entry = 32 bits in entry size = 4 bytes to read
    # entry length is the only signed number in the schema because it can be negative
    entry_length_bytes = _read_bytes_as_number(keytab, index=current_keytab_position,
                                               bytes_to_read=ENTRY_LENGTH_FIELD_SIZE_BYTES,
                                               keytab_format_version=keytab_format_version,
                                               is_signed_int=True)

    # since our string is hex, a byte is represented by 2 characters, so we move our index forwards by twice
    # the number of bytes we read
    current_keytab_position += 2 * ENTRY_LENGTH_FIELD_SIZE_BYTES
    # iterate through entries
    slot = 1
    while entry_length_bytes != 0:
        try:
            if entry_length_bytes > 0:
                start_value = current_keytab_position  # start of this entry
                # uint16_t num_components = 16 bits = 2 bytes to read
                num_components = _read_bytes_as_number(keytab, index=current_keytab_position,
                                                       bytes_to_read=NUM_COMPONENTS_FIELD_SIZE_BYTES,
                                                       keytab_format_version=keytab_format_version)
                logger.debug('Reading %s components from keytab entry in slot', num_components, slot)

                # the number of components encoded in a format v1 keytab is 1 greater than it is supposed to be
                if keytab_format_version == 1:
                    num_components -= 1

                if num_components == 0 and entry_length_bytes == 3:
                    raise KeytabEncodingException('Malformed keytab file detected. Slots are not encoded.')

                # since our string is hex, a byte is represented by 2 characters, so we move our index forwards by twice
                # the number of bytes we read
                current_keytab_position += 2 * NUM_COMPONENTS_FIELD_SIZE_BYTES

                # counted octet string realm (prefixed with 16bit length, no null terminator)
                realm_length, current_keytab_position = _read_bytes_to_number_and_then_move_position(keytab,
                                                                                                     current_keytab_position,
                                                                                                     REALM_LENGTH_FIELD_SIZE_BYTES,
                                                                                                     keytab_format_version)
                if realm_length == 0:
                    raise KeytabEncodingException('Malformed keytab file detected. A realm length of 0 is encoded to a '
                                                  'keytab.')
                realm, current_keytab_position = _read_bytes_to_string_and_then_move_position(keytab,
                                                                                              current_keytab_position,
                                                                                              realm_length)

                principal_components = []
                for i in range(num_components):
                    piece, current_keytab_position = _get_principal_component_length_and_then_read_component(keytab,
                                                                                                             current_keytab_position,
                                                                                                             keytab_format_version)
                    principal_components.append(piece)
                # principal components are separated by forwarded slashes (not encoded)
                # generally, we're likely to only have 1 or 2 components; we have 1 for user keytabs, because the
                # principal is just the username used to authenticate, and we have 2 for most server keytabs, because
                # the principal is a combination of the "service" (e.g. ssh, ldap, nfs) and the FQDN that should be used
                # to address the server during authentication.
                principal = PRINCIPAL_COMPONENT_DIVIDER.join(principal_components)

                # uint32_t name_type = 32 bits in name_type = 4 bytes to read
                # name type is not included in format version 1 keytabs
                if keytab_format_version != 1:
                    name_type, current_keytab_position = _read_bytes_to_number_and_then_move_position(keytab,
                                                                                                      current_keytab_position,
                                                                                                      PRINCIPAL_TYPE_FIELD_SIZE_BYTES,
                                                                                                      keytab_format_version)
                else:
                    name_type = 1

                # uint32_t timestamp (time key was established) = 32 bits in time = 4 bytes to read
                timestamp, current_keytab_position = _read_bytes_to_number_and_then_move_position(keytab,
                                                                                                  current_keytab_position,
                                                                                                  TIMESTAMP_FIELD_SIZE_BYTES,
                                                                                                  keytab_format_version)

                # uint8_t vno8 = 8 bits in kvno = 1 byte to read
                vno8, current_keytab_position = _read_bytes_to_number_and_then_move_position(keytab,
                                                                                             current_keytab_position,
                                                                                             VNO8_FIELD_SIZE_BYTES,
                                                                                             keytab_format_version)
                vno = vno8

                # keyblock structure: 16-bit value for encryption type and then counted_octet for key
                encryption_type, current_keytab_position = _read_bytes_to_number_and_then_move_position(keytab,
                                                                                                        current_keytab_position,
                                                                                                        ENCRYPTION_TYPE_FIELD_SIZE,
                                                                                                        keytab_format_version)

                key_length, current_keytab_position = _read_bytes_to_number_and_then_move_position(keytab,
                                                                                                   current_keytab_position,
                                                                                                   KEY_LENGTH_FIELD_SIZE_BYTES,
                                                                                                   keytab_format_version)

                # we leave our key hex encoded so we don't use read_number_and_move_position
                # since our string is hex, a byte is represented by 2 characters, so we our end index for reading our
                # key is twice its length in bytes
                hex_encoded_key = keytab[current_keytab_position:current_keytab_position + (key_length * 2)]
                current_keytab_position += key_length * 2

                # uint32_t vno if >=4 bytes left in entry_length_bytes
                current_entry_length_bytes = (current_keytab_position - start_value) // 2
                if entry_length_bytes - current_entry_length_bytes >= VNO32_FIELD_SIZE_BYTES:
                    vno32, current_keytab_position = _read_bytes_to_number_and_then_move_position(keytab,
                                                                                                  current_keytab_position,
                                                                                                  VNO32_FIELD_SIZE_BYTES,
                                                                                                  keytab_format_version)
                    # We will always pick the 32-bit vno's value if it is non-zero. Due to padding all entries in a
                    # keytab file to be the same length, the 32-bit vno field can be 0 if it's not actually populated
                    # at all (e.g. if it was generated on an older machine that didn't encode it). That's why we skip
                    # the value if it's 0
                    # https://web.mit.edu/kerberos/www/krb5-latest/doc/formats/keytab_file_format.html
                    if vno32 != 0:
                        vno = vno32

                # uint32_t flags if >=4 bytes left in entry_length_bytes
                flags = None
                current_entry_length_bytes = (current_keytab_position - start_value) // 2
                if entry_length_bytes - current_entry_length_bytes >= FLAGS_FIELD_SIZE_BYTES:
                    flags, current_keytab_position = _read_bytes_to_number_and_then_move_position(
                        keytab, current_keytab_position,
                        FLAGS_FIELD_SIZE_BYTES, keytab_format_version)

                # a keytab might not take up the full value of its entry because a tool may have overwritten an old
                # entry with a newer, smaller one. this leaves space behind. (this is also what can cause whitespace
                # to be introduced into principal names)
                # in this case, there's zero padding to the end of the entry that we can skip
                # see: https://web.mit.edu/kerberos/www/krb5-latest/doc/formats/keytab_file_format.html
                # we do this before computing our single entry value so that the entry length encoded is still accurate
                # after parsing.
                # if the dictionary details are written to data, we'll recompute the minimal length
                # and store that instead. but for the purpose of parsing, we want to return the data exactly as it
                # exists in the keytab file without alteration
                current_entry_length_bytes = (current_keytab_position - start_value) // 2
                if current_entry_length_bytes < entry_length_bytes:
                    bytes_to_move = entry_length_bytes - current_entry_length_bytes
                    # 1 byte = 2 hex characters
                    current_keytab_position += bytes_to_move * 2

                # subtract 8 from our start value to reintroduce the specification of how
                # long the keytab is, which we jump over before starting the loop.
                # this will become the bytes that we'd write to a file if we wanted to extract this
                # entry in the keytab into its own file, so we need to include the keytab length as
                # well as the prefix indicating which version of keytab format we're using in the
                # value
                single_entry_value = standalone_prefix + keytab[start_value - 8:current_keytab_position]

                # strip any whitespace from the front of the principal that may have gotten
                # there when moving keytabs to canonical form, but which doesn't matter
                # from a functional perspective
                principal = principal.lstrip()
                string_enc_type = KRB5_ENC_TYPE_VALUE_TO_ENC_TYPE_MAP[encryption_type]
                raw_key = RawKerberosKey(string_enc_type, binascii.unhexlify(hex_encoded_key))
                keytab_entry = GssKerberosKey(principal, realm, raw_key, vno,
                                              flags, timestamp, name_type, keytab_format_version)
                entries.append(keytab_entry)
            else:
                # 0 length or negative length keytabs indicate deleted entries that were not erased from the file
                # so we skip them
                logger.debug('Skipping %s length keytab due to indication of a deleted entry', abs(entry_length_bytes))
                current_keytab_position += abs(entry_length_bytes) * 2
        finally:
            entry_length_bytes, current_keytab_position = _read_bytes_to_number_and_then_move_position(keytab,
                                                                                                       current_keytab_position,
                                                                                                       ENTRY_LENGTH_FIELD_SIZE_BYTES,
                                                                                                       keytab_format_version,
                                                                                                       is_signed_int=True)
            slot += 1
    logger.debug('Extracted %s kerberos keys from keytab', len(entries))
    return entries
