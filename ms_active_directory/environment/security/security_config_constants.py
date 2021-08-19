from enum import Enum
# limit random passwords to printable characters in case callers retrieve the
# password for use in other applications/manual use.
AD_PASSWORD_CHAR_RANGE = [chr(i) for i in range(33, 127)]


class ADEncryptionType(Enum):
    DES_CBC_CRC = 1
    DES_CBC_MD5 = 2
    RC4_HMAC = 4
    AES128_CTS_HMAC_SHA1_96 = 8
    AES256_CTS_HMAC_SHA1_96 = 16

    @classmethod
    def get_ad_encryption_type_for_value(cls, val):
        return ENCRYPTION_TYPE_VALUE_TO_ENUM.get(val)


# encryption types as stored in AD are just a number that represents a bitstring.
# use this map to convert the number and our strings back and forth
ENCRYPTION_TYPE_VALUE_TO_ENUM = {
    1: ADEncryptionType.DES_CBC_CRC,
    2: ADEncryptionType.DES_CBC_MD5,
    4: ADEncryptionType.RC4_HMAC,
    8: ADEncryptionType.AES128_CTS_HMAC_SHA1_96,
    16: ADEncryptionType.AES256_CTS_HMAC_SHA1_96,
}

# users might want to use string representations of their encryption types. allow for this
# and also allow for the short form of encryption types. MMC and other AD management tools
# often use aes256-sha1 or rc4-hmac even though the actual krb5 encryption types from RFCs
# are longer (aes256-cts-hmac-sha1-96 and arcfour-hmac respectively)
ENCRYPTION_TYPE_STR_TO_ENUM = {
    'des-cbc-crc': ADEncryptionType.DES_CBC_CRC,
    'des-cbc-md5': ADEncryptionType.DES_CBC_MD5,
    'arcfour-hmac': ADEncryptionType.RC4_HMAC,
    'rc4-hmac': ADEncryptionType.RC4_HMAC,
    'aes128-cts-hmac-sha1-96': ADEncryptionType.AES128_CTS_HMAC_SHA1_96,
    'aes128-sha1': ADEncryptionType.AES128_CTS_HMAC_SHA1_96,
    'aes256-cts-hmac-sha1-96': ADEncryptionType.AES256_CTS_HMAC_SHA1_96,
    'aes256-sha1': ADEncryptionType.AES256_CTS_HMAC_SHA1_96,
}

# These encryption types are broken so I assume nobody wants to use them and have not implemented
# support for them. But they're included for completeness so that readers can more easily tell
# what's going on.
UNSUPPORTED_ENC_TYPES = {ADEncryptionType.DES_CBC_CRC, ADEncryptionType.DES_CBC_MD5}
