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

""" Utilities for interacting with security-related aspects of an AD configuration, such as the
password and encryption types.
"""
import random

from ms_active_directory import logging_utils

from typing import List, Union

from ms_active_directory.environment.security.security_config_constants import (
    AD_PASSWORD_CHAR_RANGE,
    ADEncryptionType,
    ENCRYPTION_TYPE_STR_TO_ENUM,
    ENCRYPTION_TYPE_VALUE_TO_ENUM,
    UNSUPPORTED_ENC_TYPES,
)
from ms_active_directory.exceptions import (
    InvalidLdapParameterException,
    LdapResponseDecodeException,
)


logger = logging_utils.get_logger()


def encode_password(password: str):
    """ Encodes a password to be set for an AD account via the LDAP protocol.
    Surrounds password in quotes and encodes with 'utf-16-le' as is required when setting the
    password of the computer account.
    """
    quoted_pw = '"' + password + '"'
    encoded_pw = quoted_pw.encode('utf-16-le')
    return encoded_pw


def generate_random_ad_password(password_length: int = 120):
    """ Generates a random computer password by generating random characters in the valid range for
    AD passwords until we reach the specified length.
    :param password_length: The length of the password to generate. Defaults to 120 characters if not
                            specified.
    """
    password = ''
    for count in range(password_length):
        password += random.choice(AD_PASSWORD_CHAR_RANGE)
    return password


def get_supported_encryption_types_value(encryption_types: List[Union[str, ADEncryptionType]]):
    """ Calculates the number that represents the list of encryption types by adding their values
    in the bit map.
    """
    ret = 0
    # try to normalize our list just in case the caller ignored the type hint
    normalized_types = normalize_encryption_type_list(encryption_types)
    for encryption_type in normalized_types:
        ret += encryption_type.value
    return ret


def get_supported_encryption_type_enums_from_value(encryption_types_value: int):
    """ Given the numeric representation of encryption type that comes from an entry in an AD domain,
    return a list of encryption type enums.
    """
    # we want the higher numbers first so that our encryption types are ordered by strength
    sorted_enc_type_tuples = sorted(ENCRYPTION_TYPE_VALUE_TO_ENUM.items(), reverse=True)
    encryption_types = []
    for enc_value, encryption_type_enum in sorted_enc_type_tuples:
        # use a bitwise AND to check if this encryption type is part of our encryption type value
        if enc_value & encryption_types_value:
            encryption_types.append(encryption_type_enum)
            encryption_types_value -= enc_value

    # if we have a non-zero remainder, then there's some encryption type encoded that we don't
    # recognize
    if encryption_types_value != 0:
        raise LdapResponseDecodeException('Un-parseable encryption type value from AD: {}'
                                          .format(encryption_types_value))

    return encryption_types


def normalize_encryption_type_list(encryption_types: List[Union[str, ADEncryptionType]]):
    """ Given a list of encryption types, which may be strings or enums, normalize them to enums. """
    normalized_list = []
    valid_strings = sorted(ENCRYPTION_TYPE_STR_TO_ENUM.keys())
    for encryption_type in encryption_types:
        if isinstance(encryption_type, str):
            # cast to lowercase for looking in our dict
            encryption_type = ENCRYPTION_TYPE_STR_TO_ENUM.get(encryption_type.lower())
        if encryption_type is None or not isinstance(encryption_type, ADEncryptionType):
            raise InvalidLdapParameterException('All members of an encryption type list must by encryption type enums '
                                                'or must be strings that map to encryption type enums. Valid strings '
                                                'are: {}'.format(', '.join(valid_strings)))

        if encryption_type in UNSUPPORTED_ENC_TYPES:
            raise NotImplementedError('Support for encryption type {} has not been implemented'
                                      .format(encryption_type))
        normalized_list.append(encryption_type)
    return normalized_list
