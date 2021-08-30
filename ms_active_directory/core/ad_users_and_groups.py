from ms_active_directory.environment.ldap.ldap_constants import (
    ADObject,
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


class ADUser(ADObject):

    def __init__(self, dn: str, attributes: dict, domain):
        super().__init__(dn, attributes, domain)
        # used for __repr__
        self.class_name = 'ADUser'
        self.samaccount_name = attributes.get(AD_ATTRIBUTE_SAMACCOUNT_NAME)
        self.common_name = attributes.get(AD_ATTRIBUTE_COMMON_NAME)
        self.object_classes = attributes.get(AD_ATTRIBUTE_OBJECT_CLASS)

        self.name = self.samaccount_name


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
