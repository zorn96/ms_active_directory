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

CERTIFICATE_AUTHORITY_OBJECT_CLASS = 'certificationAuthority'
TRUSTED_DOMAIN_OBJECT_CLASS = 'trustedDomain'
COMPUTER_OBJECT_CLASS = 'computer'
CONTAINER_OBJECT_CLASS = 'container'
DOMAIN_OBJECT_CLASS = 'domain'
GROUP_OBJECT_CLASS = 'group'
GROUP_POLICY_CONTAINER_CLASS = 'groupPolicyContainer'
ORGANIZATIONAL_UNIT_OBJECT_CLASS = 'organizationalUnit'
POSIX_GROUP_OBJECT_CLASS = 'posixGroup'
POSIX_USER_OBJECT_CLASS = 'posixAccount'
USER_OBJECT_CLASS = 'user'
TOP_OBJECT_CLASS = 'top'
# computers also have the user object class because they can act as users to operate
# within the domain, be a part of groups, etc.
OBJECT_CLASSES_FOR_COMPUTER = [COMPUTER_OBJECT_CLASS, USER_OBJECT_CLASS, TOP_OBJECT_CLASS]

# computers have an account control that determines things like whether they're trusted
# for
WORKSTATION_TRUST_ACCOUNT = 4096
DONT_EXPIRE_PASSWORD = 65536
ACCOUNT_DISABLED = 2
COMPUTER_ACCESS_CONTROL_VAL = WORKSTATION_TRUST_ACCOUNT + DONT_EXPIRE_PASSWORD

# used to get all attributes that aren't derived from other attributes at the time of request.
# virtual attributes are only populated if specifically requested
AD_ATTRIBUTE_GET_ALL_NON_VIRTUAL_ATTRS = '*'

# keys for common active directory attributes
AD_ATTRIBUTE_SAMACCOUNT_NAME = 'sAMAccountName'
AD_ATTRIBUTE_SECURITY_DESCRIPTOR = 'ntSecurityDescriptor'
AD_ATTRIBUTE_CANONICAL_NAME = 'canonicalName'
AD_ATTRIBUTE_COMMON_NAME = 'cn'
AD_ATTRIBUTE_DISPLAY_NAME = 'displayName'
AD_ATTRIBUTE_NAME = 'name'
AD_ATTRIBUTE_OBJECT_CLASS = 'objectClass'
AD_ATTRIBUTE_OBJECT_SID = 'objectSID'
AD_ATTRIBUTE_NETBIOS_NAME = 'nETBIOSName'

# keys for general user, group, and computer attributes
AD_ATTRIBUTE_USER_ACCOUNT_CONTROL = 'userAccountControl'
AD_ATTRIBUTE_SERVICE_PRINCIPAL_NAMES = 'servicePrincipalName'
AD_ATTRIBUTE_PASSWORD = 'unicodePwd'
# memberOf is a virtual attribute on users and groups, listing the DNs of groups that the record
# belongs to. it's less efficient to query because it's constructed on-demand in a lot of scenarios,
# and so we don't query for it by default, but use it if a user does query for it
AD_ATTRIBUTE_MEMBER_OF = 'memberOf'
# member is an attribute on groups, listing the DNs of users or groups that belong to it.
# it is part of the group record, so it's more efficient to query for and filter on
AD_ATTRIBUTE_MEMBER = 'member'
# posix attributes
AD_ATTRIBUTE_UID_NUMBER = 'uidNumber'  # posix user uid (uid is user name for ldap, uidNumber is uid)
AD_ATTRIBUTE_GID_NUMBER = 'gidNumber'  # posix group gid, or primary gid for user
AD_ATTRIBUTE_UNIX_HOME_DIR = 'unixHomeDirectory'  # homedir for a posix user
AD_ATTRIBUTE_UNIX_LOGIN_SHELL = 'loginShell'  # the login shell a user uses, e.g. /bin/bash, /bin/zsh

# keys for attributes that are relatively computer-specific
AD_ATTRIBUTE_ENCRYPTION_TYPES = 'msDS-SupportedEncryptionTypes'
AD_ATTRIBUTE_KVNO = 'msDS-KeyVersionNumber'
AD_ATTRIBUTE_DNS_HOST_NAME = 'dNSHostName'
AD_ATTRIBUTE_ADDITIONAL_DNS_HOST_NAME = 'msDS-AdditionalDnsHostName'

# keys for attributes in certificate authrities
AD_ATTRIBUTE_CA_CERT = 'caCertificate'

# keys for domains and trusted domains
AD_DOMAIN_DNS_ROOT = 'dnsRoot'
AD_DOMAIN_FUNCTIONAL_LEVEL = 'domainFunctionality'
AD_DOMAIN_SUPPORTED_SASL_MECHANISMS = 'supportedSASLMechanisms'
AD_DOMAIN_TIME = 'currentTime'
AD_SCHEMA_VERSION = 'objectVersion'
AD_TRUSTED_DOMAIN_FQDN = 'trustPartner'  # the FQDN of the trusted domain
AD_TRUSTED_DOMAIN_NETBIOS_NAME = 'flatName'  # the netbios name of the trusted domain
AD_TRUST_TYPE = 'trustType'  # indicates windows or MIT
AD_TRUST_DIRECTION = 'trustDirection'  # disabled, incoming, outgoing, bidirectional
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646fdb51a3c
AD_TRUST_ATTRIBUTES = 'trustAttributes'
AD_TRUST_POSIX_OFFSET = 'trustPosixOffset'

# keys related to policies
AD_ATTRIBUTE_GROUP_POLICY_LINK = 'gpLink'


# From windows AD docs
AD_USERNAME_RESTRICTED_CHARS = {'[', ']', ':', ';', '|', '=', '+', '*', '?', '<', '>', '/', '\\',
                                '"', ','}
# max length for a normal sAMAccountName is 20 characters, including the '$' at the end
SAM_ACCOUNT_NAME_LENGTH = 20
# if NTLM needs to be supported or any legacy clients using UNC paths need to be supported,
# then sAMAccountName must be 16 characters or less, so the computer name must be 15 characters
# or less to allow for the trailing $
LEGACY_SAM_ACCOUNT_NAME_LENGTH_LIMIT = 16

# Active Directory standards for adding computers to a domain, as well as attribute and location
# related constants for domain-scope properties like dns servers and CAs
DEFAULT_COMPUTER_SERVICES = ['HOST']
DEFAULT_COMPUTER_LOCATION = 'CN=Computers'
DNS_SERVICE_FILTER = 'DNS/*'
DOMAIN_WIDE_CONFIGURATIONS_CONTAINER = 'CN=Configuration'
DOMAIN_CONTROLLER_SCHEMA_VERSION_SEARCH_CONTAINER = 'CN=schema,' + DOMAIN_WIDE_CONFIGURATIONS_CONTAINER
DOMAIN_WIDE_PARTITIONS_CONTAINER = 'CN=Partitions,' + DOMAIN_WIDE_CONFIGURATIONS_CONTAINER
DOMAIN_POLICIES_CONTAINER = 'CN=Policies,CN=System'

# when checking if something simply exists, or getting everything at a level/subtree,
# we use this filter
FIND_ANYTHING_FILTER = '(objectClass=*)'
# other common filters
FIND_COMPUTER_FILTER = '(objectClass=Computer)'
FIND_GROUP_FILTER = '(objectClass=Group)'
FIND_USER_FILTER = '(objectClass=User)'
# if you want to filter to get records that have an attribute populated, you can check for a value
# of star
VALUE_TO_FIND_ANY_WITH_ATTRIBUTE_POPULATED = '*'

# miscellaneous values we need
UNKNOWN_USER_POSIX_UID = -1
UNKNOWN_GROUP_POSIX_GID = -1

# LDAP Error codes
OP_SUCCESS = 0
NO_SUCH_OBJECT = 32
