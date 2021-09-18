""" Constants for use in kerberos key generation and ingestion """
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

from ms_active_directory.environment.security.security_config_constants import ADEncryptionType

# constants needed to ingest keytabs and also write them out to files
# See these pages for more info on the evolution of the format beyond code comments
# http://manpages.ubuntu.com/manpages/artful/man3/krb5_fileformats.3.html
# https://web.mit.edu/kerberos/www/krb5-latest/doc/formats/keytab_file_format.html
ENCRYPTION_TYPE_FIELD_SIZE = 2  # uint16_t encryption_type = 16 bits to represent enc type = 2 bytes
ENTRY_LENGTH_FIELD_SIZE_BYTES = 4  # int32_t size of entry = 32 bits in entry size = 4 bytes
FLAGS_FIELD_SIZE_BYTES = 4  # uint32_t flags = 32 bits = 4 bytes
KEYTAB_STANDARD_LEADING_BYTES_SIZE = 1  # 0x5, a single byte, prefixes all keytab files for Kerberos v5
KEYTAB_FORMAT_SIZE_BYTES = 1  # uint8_t = 8 bits = 1 byte
KEY_LENGTH_FIELD_SIZE_BYTES = 2  # uint16_t key_length = 16 bits = 2 bytes
NUM_COMPONENTS_FIELD_SIZE_BYTES = 2  # uint16_t num_components = 16 bits = 2 bytes
REALM_LENGTH_FIELD_SIZE_BYTES = 2  # uint16_t = 16 bits in realm length = 2 bytes
PRINCIPAL_COMPONENT_LENGTH_FIELD_SIZE_BYTES = 2  # uint16_t = 16 bits in each component length = 2 bytes
PRINCIPAL_TYPE_FIELD_SIZE_BYTES = 4  # uint32_t name_type = 32 bits in name_type = 4 bytes
TIMESTAMP_FIELD_SIZE_BYTES = 4  # timestamp (time key was written) = 32 bits = 4 bytes
VNO8_FIELD_SIZE_BYTES = 1  # uint8_t vno8 = 8 bits in kvno = 1 byte
VNO32_FIELD_SIZE_BYTES = 4  # uint32_t vno32 = 32 bits in kvno = 1 byte

# this is a constant so that people can discover this comment explaining this weirdness.
# while an entire keytab file is encoded using some keytab format version, that keytab format version obviously cannot
# be or you wouldn't know how to read it.
# keytab format version is only 1 or 2, differentiating big and little endian encodings. when keytab format version
# itself is encoded, it's always encoded using format version 1 for backwards compatibility and discoverability
# purposes.
# we can be strongly certain that this will never change in the lifetime of kerberos version 5 as it breaks the ability
# of parsers to discover how to read the keytab itself
KEYTAB_FORMAT_VERSION_FOR_KEYTAB_FORMAT_VERSION = 1
# kerberos version 5 keytabs always start with 5
LEADING_BYTE_FOR_KERBEROS_V5 = 0x05
LEADING_HEX_FOR_KERBEROS_V5 = '05'
# format version 2 is newer and is preferred as it encodes more information and writes numbers in network byte order
PREFERRED_KEYTAB_FORMAT_VERSION = 2
# principal components are separated by forwarded slashes (not encoded)
PRINCIPAL_COMPONENT_DIVIDER = '/'


# here begin constants used to generate raw kerberos keys
AES_CIPHER_BLOCK_SIZE_BYTES = 16
AES_ITERATIONS_FOR_AD = 4096

SALT_FORMAT_FOR_AD = '{uppercase_realm}host{lowercase_computer_name}.{lowercase_domain}'

# AD uses a bitstring to encode supported encryption types, so the values for
# encryption types in AD are not the same as the values for encryption types
# in a kerberos keytab.
# this dictionary, and the ones below, help to make the translations of
# AD bitstring -> AD Enc Type -> KRB5 Enc Type Name -> KRB5 Enc Type Value
# and the reverse easier
AD_ENC_TYPE_TO_KRB5_ENC_TYPE_MAP = {
    ADEncryptionType.AES256_CTS_HMAC_SHA1_96: "aes256-cts-hmac-sha1-96",
    ADEncryptionType.AES128_CTS_HMAC_SHA1_96: "aes128-cts-hmac-sha1-96",
    ADEncryptionType.RC4_HMAC: "arcfour-hmac",
}
# the reverse of the above
KRB5_ENC_TYPE_TO_AD_ENC_TYPE_MAP = {value: key for key, value in AD_ENC_TYPE_TO_KRB5_ENC_TYPE_MAP.items()}


# used for reading in keytabs. AD only supports a small handful of these (from the map above)
# but we include all encryption types here for completeness.
KRB5_ENC_TYPE_VALUE_TO_ENC_TYPE_MAP = {
    26: "camellia256-cts-cmac",  # RFC6803
    25: "camellia128-cts-cmac",  # RFC6803
    24: "arcfour-hmac",  # RFC8429. This is arcfour-hmac exportable. but the exportable doesn't matter here, just treat it as arcfour for user views
    23: "arcfour-hmac",  # RFC8429
    # 21 and 22 are unassigned
    20: "aes256-cts-hmac-sha384-192",  # RFC8009
    19: "aes128-cts-hmac-sha256-128",  # RFC8009
    18: "aes256-cts-hmac-sha1-96",  # RFC3962
    17: "aes128-cts-hmac-sha1-96",  # RFC3962
    16: "des3-cbc-sha1",  # RFC8429

    # 9 through 15 should never actually be used in NFS or SMB kerberos. but it doesn't hurt to be
    # future-proof
    15: "des-ede3-cbc-Env-OID",  # RFC4556
    14: "rsaES-OAEP-ENV-OID",  # RFC4556
    13: "rsaEncryption-EnvOID",  # RFC4556
    12: "arc2-cbc-EnvOID",  # RFC4556
    11: "sha1WithRSAEncryption-CmsOID",  # RFC4556
    10: "md5WithRSAEncryption-CmsOID",  # RFC4556
    9: "dsaWithSHA1-CmsOID",  # RFC4556

    8: "des-hmac-sha1",
    7: "des3-cbc-sha1",  # RFC8429
    # 6 is reserved RFC3961
    5: "des3-cbc-md5",  # RFC8429
    # 4 is reserved RFC3961
    3: "des-cbc-md5",  # RFC6649
    2: "des-cbc-md4",  # RFC6649
    1: "des-cbc-crc",  # RFC6649
}
# this is a reverse of the above
KRB5_ENC_TYPE_TO_ENC_TYPE_VALUE_MAP = {value: key for key, value in KRB5_ENC_TYPE_VALUE_TO_ENC_TYPE_MAP.items()}
NAME_TYPE_VALUE_TO_NAME_TYPE_MAP = {
    0: "KRB5_NT_UNKNOWN",
    1: "KRB5_NT_PRINCIPAL",
    2: "KRB5_NT_SRV_INST",
    5: "KRB5_NT_UID",
}
DEFAULT_UNKNOWN_NAME_TYPE = 0
AD_DEFAULT_NAME_TYPE = 1

DEFAULT_KRB5_KEYTAB_FILE_LOCATION = '/etc/krb5.keytab'
