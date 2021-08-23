import copy

from ms_active_directory.environment.ldap.ldap_constants import (
    AD_ATTRIBUTE_COMMON_NAME,
    AD_ATTRIBUTE_GID_NUMBER,
    AD_ATTRIBUTE_OBJECT_CLASS,
    AD_ATTRIBUTE_SAMACCOUNT_NAME,
    AD_ATTRIBUTE_UID_NUMBER,
    AD_ATTRIBUTE_UNIX_HOME_DIR,
    AD_ATTRIBUTE_UNIX_LOGIN_SHELL,
    UNKNOWN_GROUP_POSIX_GID,
    UNKNOWN_USER_POSIX_UID,
)
from ms_active_directory.environment.ldap.ldap_format_utils import (
    normalize_object_location_in_domain
)


class ADObject:

    def __init__(self, dn: str, attributes: dict, domain):
        self.distinguished_name = dn
        self.domain = domain
        self.all_attributes = attributes if attributes else {}
        # used for __repr__
        self.class_name = 'ADObject'

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


class ADUser(ADObject):

    def __init__(self, dn: str, attributes: dict, domain):
        super().__init__(dn, attributes, domain)
        # used for __repr__
        self.class_name = 'ADUser'
        self.samaccount_name = attributes.get(AD_ATTRIBUTE_SAMACCOUNT_NAME)
        self.common_name = attributes.get(AD_ATTRIBUTE_COMMON_NAME)
        self.object_classes = attributes.get(AD_ATTRIBUTE_OBJECT_CLASS)

        self.name = self.samaccount_name
        # to get the location of a user, remove their common name from the front and the domain's
        # domain components from the end
        rdn_of_user = normalize_object_location_in_domain(dn, self.domain.get_domain_dns_name())
        user_piece = 'CN=' + self.common_name
        self.location = rdn_of_user[len(user_piece)+1:]


class ADPosixUser(ADUser):

    def __init__(self, dn: str, attributes: dict, domain):
        super().__init__(dn, attributes, domain)
        # used for __repr__
        self.class_name = 'ADPosixUser'
        # posix attributes aren't actually mandatory for posix objects in AD, so we're not guaranteed these
        # exist
        self.uid = UNKNOWN_USER_POSIX_UID
        # uidNumber will come back as a singleton list
        if AD_ATTRIBUTE_UID_NUMBER in attributes and attributes.get(AD_ATTRIBUTE_UID_NUMBER):
            self.uid = int(attributes.get(AD_ATTRIBUTE_UID_NUMBER)[0])

        self.gid = UNKNOWN_GROUP_POSIX_GID
        # gidNumber will come back as a singleton list
        if AD_ATTRIBUTE_GID_NUMBER in attributes and attributes.get(AD_ATTRIBUTE_GID_NUMBER):
            self.gid = int(attributes.get(AD_ATTRIBUTE_GID_NUMBER)[0])

        self.unix_home_directory = None
        if AD_ATTRIBUTE_UNIX_HOME_DIR in attributes and attributes.get(AD_ATTRIBUTE_UNIX_HOME_DIR):
            self.unix_home_directory = attributes.get(AD_ATTRIBUTE_UNIX_HOME_DIR)[0]

        self.login_shell = None
        if AD_ATTRIBUTE_UNIX_LOGIN_SHELL in attributes and attributes.get(AD_ATTRIBUTE_UNIX_LOGIN_SHELL):
            self.login_shell = attributes.get(AD_ATTRIBUTE_UNIX_LOGIN_SHELL)[0]


class ADGroup(ADObject):

    def __init__(self, dn: str, attributes: dict, domain):
        super().__init__(dn, attributes, domain)
        # used for __repr__
        self.class_name = 'ADGroup'
        self.samaccount_name = attributes.get(AD_ATTRIBUTE_SAMACCOUNT_NAME)
        self.common_name = attributes.get(AD_ATTRIBUTE_COMMON_NAME)
        self.object_classes = attributes.get(AD_ATTRIBUTE_OBJECT_CLASS)

        self.name = self.samaccount_name
        # to get the location of a user, remove their common name from the front and the domain's
        # domain components from the end
        rdn_of_user = normalize_object_location_in_domain(dn, self.domain.get_domain_dns_name())
        user_piece = 'CN=' + self.common_name
        self.location = rdn_of_user[len(user_piece)+1:]


class ADPosixGroup(ADGroup):

    def __init__(self, dn: str, attributes: dict, domain):
        super().__init__(dn, attributes, domain)
        # used for __repr__
        self.class_name = 'ADPosixGroup'
        # posix attributes aren't actually mandatory for posix objects in AD, so we're not guaranteed these
        # exist
        self.gid = UNKNOWN_GROUP_POSIX_GID
        # gidNumber will come back as a singleton list
        if AD_ATTRIBUTE_GID_NUMBER in attributes and attributes.get(AD_ATTRIBUTE_GID_NUMBER):
            self.gid = int(attributes.get(AD_ATTRIBUTE_GID_NUMBER)[0])
