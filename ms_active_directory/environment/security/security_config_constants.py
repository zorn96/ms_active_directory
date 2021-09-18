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


# Constants related to Security Descriptor parsing

# used to construct controls
AD_SERVER_SECURITY_DESCRIPTOR_FLAGS_OID = '1.2.840.113556.1.4.801'
LENGTH_DESCRIPTOR_FMT = '-%s'

# Sacl and Dacl
SACL = 'Sacl'
DACL = 'Dacl'

# Offset constants
OFFSET_OWNER = 'OffsetOwner'
OFFSET_GROUP = 'OffsetGroup'
OFFSET_SACL = 'OffsetSacl'
OFFSET_DACL = 'OffsetDacl'

# SID constants
OWNER_SID = 'OwnerSid'
GROUP_SID = 'GroupSid'
SID = 'Sid'

# ACL constants
ACE_COUNT = 'AceCount'
ACL_REVISION = 'AclRevision'
ACL_SIZE = 'AclSize'

# ACE constants
ACE_BODY = 'Ace'
ACE_FLAGS = 'AceFlags'
ACE_LEN = 'AceLen'
ACE_SIZE = 'AceSize'
ACE_TYPE = 'AceType'
ACE_TYPE_NAME = 'TypeName'

# Object authority constants
IDENTIFIER_AUTHORITY = 'IdentifierAuthority'
SUB_AUTHORITY = 'SubAuthority'
SUB_AUTHORITY_COUNT = 'SubAuthorityCount'
SUB_AUTHORITY_LEN = 'SubLen'

# Object type constants
INHERITED_OBJECT_TYPE = 'InheritedObjectType'
INHERITED_OBJECT_TYPE_LEN = 'InheritedObjectTypeLen'
OBJECT_TYPE = 'ObjectType'
OBJECT_TYPE_LEN = 'ObjectTypeLen'

# General constants used a bit across AD
APPLICATION_DATA = 'ApplicationData'
CONTROL = 'Control'
DATA = 'Data'
DATA_LEN = 'DataLen'
FLAGS = 'Flags'
MASK = 'Mask'
REVISION = 'Revision'
SBZ1 = 'Sbz1'
SBZ2 = 'Sbz2'
VALUE = 'Value'

# AD has some "well known SIDs" that people may want to use.
# These are independent of the actual domain
# see: https://docs.microsoft.com/en-us/windows/win32/secauthz/well-known-sids
# also see: https://docs.microsoft.com/en-us/windows/security/identity-protection/access-control/security-identifiers


class WellKnownSID(Enum):
    # The first 5 are universally well known even outside of windows, while the later ones are
    # only well-known within the windows security model
    NULL = 'S-1-0-0'
    EVERYONE = 'S-1-1-0'
    # the following 2 will refer to the user/computer that created an object and the primary group SID
    # of that user/computer
    CREATOR_OWNER = 'S-1-3-0'
    CREATOR_GROUP = 'S-1-3-1'

    # the following all exist within the windows NT authority (S-1-5) and are well-known and meaningful on
    # windows systems.
    # I've left out some of these because, to be frank, I don't think it's worthwhile to include things like
    # "People on dial-up modems"
    SERVICE = 'S-1-5-6'  # accounts authorized to act as a service
    ANONYMOUS = 'S-1-5-7'  # anonymous users (e.g. an ldap session bound with no user/password)
    ENTERPRISE_CONTROLLERS = 'S-1-5-9'  # enterprise controllers
    SELF = 'S-1-5-10'  # referring to an object's self
    AUTHENTICATED_USERS = 'S-1-5-11'  # all authenticated users. does not include guest accounts
    LOCAL_OS = 'S-1-5-18'  # The operating system

    # default domain groups
    ADMINISTRATORS_BUILT_IN_GROUP = 'S-1-5-32-544'
    USERS_BUILT_IN_GROUP = 'S-1-5-32-545'
    GUESTS_BUILT_IN_GROUP = 'S-1-5-32-546'
    # Power users can create local users/groups, add/remove printers and file shares, and a few other things
    POWER_USERS_BUILT_IN_GROUP = 'S-1-5-32-547'
    # Can create/modify/delete user, group, and computer accounts across the domain
    ACCOUNT_OPERATORS_BUILT_IN_GROUP = 'S-1-5-32-548'
    # Can manage services, backup/restore files, format the hard disk, and do some other things
    SERVER_OPERATORS_BUILT_IN_GROUP = 'S-1-5-32-549'
    # Can manager printers and queues
    PRINT_OPERATORS_BUILT_IN_GROUP = 'S-1-5-32-550'
    # Can manage backup and restore
    BACKUP_OPERATORS_BUILT_IN_GROUP = 'S-1-5-32-551'
    # manages replication services
    REPLICATORS_BUILT_IN_GROUP = 'S-1-5-32-552'
    # users who can login interactively using RDP
    REMOTE_DESKTOP_USERS_BUILT_IN_GROUP = 'S-1-5-32-555'
    # Network operators can configure networking, duh
    NETWORK_CONFIG_OPERATORS_BUILT_IN_GROUP = 'S-1-5-32-556'
    # SKIPPING LOTS OF NOT SUPER COMMON GROUPS TO SAVE TYPING
    # ...
    # These users can use WS-Management for WMI namespaces
    REMOTE_MANAGEMENT_USERS_BUILT_IN_GROUP = 'S-1-5-32-580'
    # membership controlled by the OS
    ALL_SERVICES_BUILT_IN_GROUP = 'S-1-5-80-0'
