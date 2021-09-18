""" Kerberos Key Generator Module

This module contains functions to generate kerberos keys based on a given encryption
type and password bytes.
Optionally, the bytes for a salt may be supplied, and iteration count may be specified
for those encryption types that support salting or multiple iterations.
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


from ms_active_directory import logging_utils

from functools import reduce

from Crypto.Util.number import GCD
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, MD4, SHA  # SHA is SHA1, not SHA256 or SHA384
from Crypto.Protocol.KDF import PBKDF2  # password-based key derivation function

from ms_active_directory.core.ad_kerberos_keys import RawKerberosKey

from ms_active_directory.environment.kerberos.kerberos_constants import (
    AD_ENC_TYPE_TO_KRB5_ENC_TYPE_MAP,
    AES_CIPHER_BLOCK_SIZE_BYTES,
    AES_ITERATIONS_FOR_AD,
    SALT_FORMAT_FOR_AD,
)
from ms_active_directory.environment.security.security_config_constants import (
    ADEncryptionType,
    ENCRYPTION_TYPE_STR_TO_ENUM,
)

logger = logging_utils.get_logger()


def ad_password_string_to_key(ad_encryption_type: ADEncryptionType, ad_computer_name: str, ad_password: str,
                              ad_domain_dns_name: str, ad_auth_realm: str = None) -> RawKerberosKey:
    """ Given an encryption type, a computer name, a password, and a domain, generate the raw kerberos key for an AD
    account. Optionally, a realm may be specified if the kerberos realm for the domain is not the domain itself
    (this may be the case for subdomains or when AD is not the central authentication for an environment).
    :param ad_encryption_type: The kerberos encryption type to use for generating the key.
    :param ad_computer_name: The name of the computer in AD. This is the sAMAccountName without the trailing $.
    :param ad_password: The password of the computer.
    :param ad_domain_dns_name: The DNS name of the AD domain where the computer exists.
    :param ad_auth_realm: The realm used by the domain for authentication. If not specified, defaults to the domain
                          in all captial letters.
    """
    ad_auth_realm = ad_auth_realm if ad_auth_realm else ad_domain_dns_name
    # be forgiving to those who don't read the docs
    if ad_computer_name.endswith('$'):
        ad_computer_name = ad_computer_name[:-1]
    salt_str = _format_aes_salt_for_ad(ad_computer_name, ad_domain_dns_name, ad_auth_realm)
    # we can just always pass in a salt and iterations, and unsalted encryption types (e.g. rc4-hmac) will ignore it
    return password_string_to_key(ad_encryption_type, ad_password, salt_str, AES_ITERATIONS_FOR_AD)


def password_bytes_to_key(ad_encryption_type: ADEncryptionType, password_bytes: bytes, salt_bytes: bytes = None,
                          iterations: int = None) -> RawKerberosKey:
    """ Given an encryption type, password bytes, and optionally salt bytes and an iteration count, generate and
    return a kerberos key for the specified encryption type using the other parameters.
    """
    e = _get_enc_type_profile(ad_encryption_type)
    return e.password_bytes_to_key(password_bytes, salt_bytes, iterations)


def password_string_to_key(ad_encryption_type: ADEncryptionType, password_string: str, salt_string: str = None,
                           iterations: int = None) -> RawKerberosKey:
    """ Given an encryption type, a string password, and optionally a string salt and an iteration count, generate and
    return a kerberos key for the specified encryption type using the other parameters.
    """
    password_bytes = password_string.encode('UTF-8')
    salt_bytes = salt_string.encode('UTF-8') if salt_string is not None else salt_string
    return password_bytes_to_key(ad_encryption_type, password_bytes, salt_bytes=salt_bytes, iterations=iterations)


def _get_enc_type_profile(enc_type: ADEncryptionType):
    if isinstance(enc_type, str):
        enc_type = ENCRYPTION_TYPE_STR_TO_ENUM.get(enc_type.lower())
    if enc_type not in AD_ENC_TYPE_TO_KRB5_ENC_TYPE_MAP:
        raise ValueError('Invalid or unsupported encryption type for kerberos key generation {}'
                         .format(enc_type))
    ad_enc_to_profile = {
        _AES128CTS.enc_type: _AES128CTS,
        _AES256CTS.enc_type: _AES256CTS,
        _RC4.enc_type: _RC4
    }
    return ad_enc_to_profile[enc_type]


def _format_aes_salt_for_ad(computer_name: str, domain: str, realm: str):
    """ Computer names and domains can be specified in any casing. However, DNS names are case insensitive, as are
    computer names in AD.
    However, salts for AES encryption are not case insensitive because AES doesn't cater to Active Directory's desires.
    The result is a confusing standard that we try to gracefully accommodate by converting casing as needed so that we,
    as a client, can generate keys the same way AD does internally.
    AD also uses different information in its salt than other kerberos realms, so we handle that here as well.
    Normal kerberos realms just do [case sensitive realm][case sensitive principal], which runs contrary to AD's notion
    of domain name/realm name and principals directly translating into DNS and therefore being case insensitive.
    """
    # in the AES salt for AD, the realm piece is always uppercase
    upper_realm = realm.upper()
    # in the AES salt for AD, the domain is always lowercase
    lower_domain = domain.lower()
    # active directory names are case insensitive, so AD decided that salts should always use the lower case name for
    # the computer, because the salting of AES is not case insensitive
    lower_computer_name = computer_name.lower()
    salt_string = SALT_FORMAT_FOR_AD.format(lowercase_computer_name=lower_computer_name,
                                            uppercase_realm=upper_realm,
                                            lowercase_domain=lower_domain)
    return salt_string


def _zeropad(byte_string: bytes, pad_size: int) -> bytes:
    # Return byte_string padded with 0 bytes to a multiple of pad_size.
    padlen = (pad_size - (len(byte_string) % pad_size)) % pad_size
    return byte_string + b'\0' * padlen


def _nfold(string_to_fold: str, nbytes: int) -> bytes:
    """ This function is really hard to read because heavy math doesn't translate super well to
    python. This would actually be more readable in python2 where you can freely float between
    bytes and strings (which might be more readable computing byte-based functions using
    shared secrets that are strings).
    This function applies the n-fold operation defined in RFC3961 to a byte string of length
    nbytes
    https://tools.ietf.org/html/rfc3961#section-5.1
    """

    def _rotate_right(byte_string_to_rotate: str, nbits: int):
        """ Rotate the bytes in str to the right by nbits bits. """
        indices = list(range(len(byte_string_to_rotate)))
        num_bytes, remain = (nbits // 8) % len(byte_string_to_rotate), nbits % 8
        return b''.join(bytes([(ord(byte_string_to_rotate[i - num_bytes]) >> remain) |
                               ((ord(byte_string_to_rotate[i - num_bytes - 1]) << (8 - remain)) & 0xff)])
                        for i in indices)

    def _add_ones_complement(byte_str_1: bytes, byte_str_2: bytes):
        """ Add equal-length strings together with end-around carry. """
        n = len(byte_str_1)
        v = [a + b for a, b in list(zip(byte_str_1, byte_str_2))]
        # Propagate carry bits to the left until there aren't any left.
        while any(x & ~0xff for x in v):
            v = [(v[i - n + 1] >> 8) + (v[i] & 0xff) for i in list(range(n))]
        return b''.join(bytes([x]) for x in v)

    # Concatenate copies of string_to_fold to produce the least common multiple
    # of len(string_to_fold) and nbytes, rotating each copy of string_to_fold to the right
    # by 13 bits times its list position.
    byte_length_to_fold = len(string_to_fold)
    lcm = int(nbytes * byte_length_to_fold / GCD(nbytes, byte_length_to_fold))
    big_byte_str = b''.join((_rotate_right(string_to_fold, 13 * i) for i in range(lcm // byte_length_to_fold)))
    # Decompose the concatenation into slices of length nbytes, and add them together as
    # big-endian ones' complement integers.
    slices = [big_byte_str[p:p + nbytes] for p in list(range(0, lcm, nbytes))]
    result = reduce(_add_ones_complement, slices)
    return result


class _EncTypeProfile(object):
    # Base class for enc_type profiles.  Usable enc_type classes must define:
    #   * enc_type: enc_type number
    #   * key_size: protocol size of key in bytes
    #   * seed_size: random_to_key input size in bytes
    #   * password_bytes_to_key
    enc_type = None
    key_size = None
    seed_size = None

    @classmethod
    def password_bytes_to_key(cls, password_bytes: bytes, salt_bytes: bytes = None, iterations: int = None):
        raise NotImplementedError('Child classes must implement password_bytes_to_key')


class _SimplifiedEnctype(_EncTypeProfile):
    # Base class for enc_types using the RFC 3961 simplified profile.
    # Defines the encrypt, decrypt, and prf methods.  Subclasses must
    # define:
    #   * block_size: The block size used for any CBC computation
    #   * basic_encrypt: Underlying CBC/CTS cipher, which is used for some key generation
    block_size = 1

    @classmethod
    def basic_encrypt(cls, key: RawKerberosKey, plaintext_bytes: bytes):
        """ Placeholder to force child classes to implement this """
        raise NotImplementedError(
            'This function must be implemented by child classes that need key derivation or encryption')

    @classmethod
    def derive(cls, key: RawKerberosKey, constant: str) -> RawKerberosKey:
        """ Derive a kerberos key from some key and some constant.
        By mixing a key with a constant, you can essentially make the key
        "service-unique" so that if I use a password to generate a kerberos
        key as well as a key for some other service, they will not be the
        same key, even if they use the same encryption type.
        """
        rnd_seed = b''
        # RFC 3961 says to n-fold the constant only if it is shorter than the cipher block size
        # N-fold is a no-op if the constant is equal to the cipher block size.
        # And unix implementations all n-fold when the constant is greater than the cipher
        # block size. The RFC also gives examples of n-folding both shorter and longer constants
        # So we just always n-fold the constant here
        plaintext_bytes = _nfold(constant, cls.block_size)
        while len(rnd_seed) < cls.seed_size:
            ciphertext_bytes = cls.basic_encrypt(key, plaintext_bytes)
            rnd_seed += ciphertext_bytes
            # use our ciphertext output as the next plaintext input
            plaintext_bytes = ciphertext_bytes
        # trim our generated encrypted seed to form our key_bytes
        trimmed_seed = rnd_seed[:cls.seed_size]
        return RawKerberosKey(cls.enc_type, trimmed_seed)


class _AESEnctype(_SimplifiedEnctype):
    # Base class for aes128-cts and aes256-cts.
    # cts = cipher-text stealing
    # AD only supports aes256-sha1 and aes128-sha1 right now. but if we do generic kdc support, we may add sha256/sha384
    # as options for other AES types, so make this a class variable.
    # AD might also add sha256/sha384 some day. SHA1 still has weak collision resistance, making it suitable for
    # kerberos keys, even though it was broken for strong collision resistance in 2019. but it could be broken for
    # weak collision resistance soon, and so newer AD may very likely start supporting sha256 and sha384
    sha_version = SHA
    # AES candidates, regardless of key size, always uses the same block size, which is 16 bytes
    # this is formalized in RFC3602
    block_size = AES_CIPHER_BLOCK_SIZE_BYTES

    @classmethod
    def password_bytes_to_key(cls, password_bytes: bytes, salt_bytes: bytes, iterations: int = 1) -> RawKerberosKey:
        # this is the pseudo-random function needed for our password-based key
        # derivation for AES
        prf = lambda p, s: HMAC.new(p, s, cls.sha_version).digest()
        # we then compute our seed by running that pseudo-random function
        # over our password bytes and salt bytes for some number of iterations.
        # each subsequent iteration's input will be based on the previous
        # iterations output. this is the basic premise of the AES algorithm.
        # Seed size varies between AES128, AES256, etc. and influences the size
        # of the seed (in bytes) that we pack into.
        # PBKDF2 can take a bytestring or string, so ignore the warning about this
        # being bytes while a string is expected
        seed = PBKDF2(password_bytes, salt_bytes, cls.seed_size, iterations, prf)
        # our first key is a temporary key based off our our seed, which was
        # generated from our password
        tkey = RawKerberosKey(cls.enc_type, seed)
        # our final computed key is a derivation of our temporary key with a usage
        # string 'kerberos', which ensures that AES-based keys for other protocols
        # will be different, even with the same password and salt.
        # this element of AES is a big reason why it's better to save kerberos
        # keys than passwords - because getting the password gives you access over
        # every protocol, while getting a key only gives you kerberos.
        return cls.derive(tkey, 'kerberos')

    @classmethod
    def basic_encrypt(cls, key: RawKerberosKey, plaintext_bytes: bytes) -> bytes:
        # CBC = cipher block chaining
        aes = AES.new(key.key_bytes, AES.MODE_CBC, b'\0' * cls.block_size)
        # pad our plaintext to a multiple of the AES block size
        ctext = aes.encrypt(_zeropad(plaintext_bytes, cls.block_size))
        if len(plaintext_bytes) > cls.block_size:
            # Swap the last two ciphertext blocks and truncate the
            # final block to match the plaintext length.
            lastlen = len(plaintext_bytes) % cls.block_size or cls.block_size
            last_block_index = -1 * cls.block_size
            second_to_last_block_index = -2 * cls.block_size
            truncated_second_to_last_block = ctext[second_to_last_block_index:second_to_last_block_index][:lastlen]
            ctext = ctext[:second_to_last_block_index] + ctext[last_block_index:] + truncated_second_to_last_block
        return ctext


class _AES128CTS(_AESEnctype):
    enc_type = ADEncryptionType.AES128_CTS_HMAC_SHA1_96
    # 16 bytes * 8 bits/byte = 128 bits, AES128
    key_size = 16
    seed_size = 16


class _AES256CTS(_AESEnctype):
    enc_type = ADEncryptionType.AES256_CTS_HMAC_SHA1_96
    # 32 bytes * 8 bits/byte = 256 bits, AES256
    key_size = 32
    seed_size = 32


class _RC4(_EncTypeProfile):
    enc_type = ADEncryptionType.RC4_HMAC
    key_size = 16
    seed_size = 16

    @classmethod
    def password_bytes_to_key(cls, password_bytes: bytes, salt_bytes: bytes = None,
                              iterations: bytes = None) -> RawKerberosKey:
        # RC4 requires a shared secret that fits in the UTF8 encoding, which is
        # part of why it's considered a little less secure (smaller space).
        # we then convert the shared secret to utf16 (little-endian) and generate
        # they key by computing the MD4 digest of that utf16 string.
        # This is very straightforward and easy.
        utf16_string = password_bytes.decode('UTF-8').encode('UTF-16LE')
        return RawKerberosKey(cls.enc_type, MD4.new(utf16_string).digest())
