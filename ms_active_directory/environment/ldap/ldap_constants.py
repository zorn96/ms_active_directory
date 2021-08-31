import copy
from ldap3.utils.dn import parse_dn

CERTIFICATE_AUTHORITY_OBJECT_CLASS = 'certificationAuthority'
TRUSTED_DOMAIN_OBJECT_CLASS = 'TrustedDomain'
COMPUTER_OBJECT_CLASS = 'computer'
GROUP_OBJECT_CLASS = 'group'
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
AD_ATTRIBUTE_COMMON_NAME = 'cn'
AD_ATTRIBUTE_OBJECT_CLASS = 'objectClass'
AD_ATTRIBUTE_OBJECT_SID = 'objectSID'

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
AD_DOMAIN_FUNCTIONAL_LEVEL = 'domainFunctionality'
AD_DOMAIN_SUPPORTED_SASL_MECHANISMS = 'supportedSASLMechanisms'
AD_DOMAIN_TIME = 'currentTime'
AD_SCHEMA_VERSION = 'objectVersion'
AD_TRUSTED_DOMAIN_NAME = 'trustPartner'  # the netbios name of the trusted domain
AD_TRUST_TYPE = 'trustType'  # indicates windows or MIT
AD_TRUST_DIRECTION = 'trustDirection'  # disabled, incoming, outgoing, bidirectional
# TODO: implement decoding of more detailed trust info
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646fdb51a3c
AD_TRUST_ATTRIBUTES = 'trustAttributes'


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
DOMAIN_CONTROLLER_SCHEMA_VERSION_SEARCH_CONTAINER = 'CN=schema,CN=Configuration'
DOMAIN_WIDE_CONFIGURATIONS_CONTAINER = 'CN=Configuration'

# when checking if something simply exists, or getting everything at a level/subtree,
# we use this filter
FIND_ANYTHING_FILTER = '(objectClass=*)'
FIND_COMPUTER_FILTER = '(objectClass=Computer)'
FIND_GROUP_FILTER = '(objectClass=Group)'
FIND_USER_FILTER = '(objectClass=User)'

# miscellaneous values we need
UNKNOWN_USER_POSIX_UID = -1
UNKNOWN_GROUP_POSIX_GID = -1


# the parent of all ADObjects, defined here to avoid risk of circular imports

class ADObject:

    def __init__(self, dn: str, attributes: dict, domain):
        self.distinguished_name = dn
        self.domain = domain
        self.all_attributes = attributes if attributes else {}
        # used for __repr__
        self.class_name = 'ADObject'

        # to get the location of an object, we split up all of the DN components and remove the
        # first component (the object itself) and the domain components. reassembling what remains
        # gives us the relative dn of the object's container
        dn_pieces = parse_dn(dn, escape=True)
        superlative_dn_pieces = dn_pieces[1:]
        superlative_dn_pieces_without_domain = [piece for piece in superlative_dn_pieces if piece[0].lower() != 'dc']
        reconstructed_pieces = [piece[0] + '=' + piece[1] + piece[2] for piece in superlative_dn_pieces_without_domain]
        self.location = ''.join(reconstructed_pieces)

    def get(self, attribute_name: str, unpack_one_item_lists=False):
        """ Get an attribute about the group that isn't explicitly tracked as a member """
        val = self.all_attributes.get(attribute_name)
        # there's a lot of 1-item lists from the ldap3 library
        if isinstance(val, list) and len(val) == 1 and unpack_one_item_lists:
            return copy.deepcopy(val[0])
        return copy.deepcopy(val)

    def __repr__(self):
        attrs = self.all_attributes.__repr__() if self.all_attributes else 'None'
        domain = self.domain.__repr__()
        return ('{type}(dn={dn}, attributes={attrs}, domain={domain})'
                .format(type=self.class_name, dn=self.distinguished_name, attrs=attrs, domain=domain))

    def __str__(self):
        return self.__repr__()
