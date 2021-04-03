
COMPUTER_OBJECT_CLASS = 'computer'
USER_OBJECT_CLASS = 'user'
TOP_OBJECT_CLASS = 'top'
# computers also have the user object class because they can act as users to operate
# within the domain, be a part of groups, etc.
OBJECT_CLASSES_FOR_COMPUTER = [COMPUTER_OBJECT_CLASS, USER_OBJECT_CLASS, TOP_OBJECT_CLASS]

# computers have an account control that determines things like whether they're trusted
# for
WORKSTATION_TRUST_ACCOUNT = 4096
DONT_EXPIRE_PASSWORD = 65536
COMPUTER_ACCESS_CONTROL_VAL = WORKSTATION_TRUST_ACCOUNT + DONT_EXPIRE_PASSWORD

# keys for active directory attributes
AD_ATTRIBUTE_SAMACCOUNT_NAME = 'sAMAccountName'
AD_ATTRIBUTE_COMMON_NAME = 'cn'
AD_ATTRIBUTE_USER_ACCOUNT_CONTROL = 'userAccountControl'
AD_ATTRIBUTE_SERVICE_PRINCIPAL_NAMES = 'servicePrincipalName'
AD_ATTRIBUTE_ENCRYPTION_TYPES = 'msDS-SupportedEncryptionTypes'
AD_ATTRIBUTE_KVNO = 'msDS-KeyVersionNumber'
AD_ATTRIBUTE_PASSWORD = 'unicodePwd'
AD_ATTRIBUTE_DNS_HOST_NAME = 'dNSHostName'
AD_ATTRIBUTE_ADDITIONAL_DNS_HOST_NAME = 'msDS-AdditionalDnsHostName'

# From windows AD docs
AD_USERNAME_RESTRICTED_CHARS = {'[', ']', ':', ';', '|', '=', '+', '*', '?', '<', '>', '/', '\\',
                                '"', ','}
# max length for a normal sAMAccountName is 20 characters, including the '$' at the end
SAM_ACCOUNT_NAME_LENGTH = 20
# if NTLM needs to be supported or any legacy clients using UNC paths need to be supported,
# then sAMAccountName must be 16 characters or less, so the computer name must be 15 characters
# or less to allow for the trailing $
LEGACY_SAM_ACCOUNT_NAME_LENGTH_LIMIT = 16

# Active Directory standards for adding computers to a domain
DEFAULT_COMPUTER_SERVICES = ['HOST']
DEFAULT_COMPUTER_LOCATION = 'CN=Computers'

# when checking if something simply exists, or getting everything at a level/subtree,
# we use this filter
FIND_ANYTHING_FILTER = '(objectClass=*)'
