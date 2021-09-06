import copy

from ldap3.utils.dn import parse_dn
from typing import TYPE_CHECKING
if TYPE_CHECKING:
    from ms_active_directory.core.ad_domain import ADDomain


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


# the parent of all ADObjects, defined here to avoid risk of circular imports

class ADObject:

    def __init__(self, dn: str, attributes: dict, domain: 'ADDomain'):
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


class ADComputer(ADObject):

    def __init__(self, dn: str, attributes: dict, domain: 'ADDomain'):
        super().__init__(dn, attributes, domain)
        # used for __repr__
        self.class_name = 'ADComputer'
        self.samaccount_name = attributes.get(AD_ATTRIBUTE_SAMACCOUNT_NAME)
        self.common_name = attributes.get(AD_ATTRIBUTE_COMMON_NAME)
        self.object_classes = attributes.get(AD_ATTRIBUTE_OBJECT_CLASS)

        self.name = self.samaccount_name
        if self.name.endswith('$'):
            self.name = self.name[:-1]


class ADUser(ADObject):

    def __init__(self, dn: str, attributes: dict, domain: 'ADDomain'):
        super().__init__(dn, attributes, domain)
        # used for __repr__
        self.class_name = 'ADUser'
        self.samaccount_name = attributes.get(AD_ATTRIBUTE_SAMACCOUNT_NAME)
        self.common_name = attributes.get(AD_ATTRIBUTE_COMMON_NAME)
        self.object_classes = attributes.get(AD_ATTRIBUTE_OBJECT_CLASS)

        self.name = self.samaccount_name


class ADPosixUser(ADUser):

    def __init__(self, dn: str, attributes: dict, domain: 'ADDomain'):
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

    def __init__(self, dn: str, attributes: dict, domain: 'ADDomain'):
        super().__init__(dn, attributes, domain)
        # used for __repr__
        self.class_name = 'ADGroup'
        self.samaccount_name = attributes.get(AD_ATTRIBUTE_SAMACCOUNT_NAME)
        self.common_name = attributes.get(AD_ATTRIBUTE_COMMON_NAME)
        self.object_classes = attributes.get(AD_ATTRIBUTE_OBJECT_CLASS)

        self.name = self.samaccount_name


class ADPosixGroup(ADGroup):

    def __init__(self, dn: str, attributes: dict, domain: 'ADDomain'):
        super().__init__(dn, attributes, domain)
        # used for __repr__
        self.class_name = 'ADPosixGroup'
        # posix attributes aren't actually mandatory for posix objects in AD, so we're not guaranteed these
        # exist
        self.gid = UNKNOWN_GROUP_POSIX_GID
        # gidNumber will come back as a singleton list
        if AD_ATTRIBUTE_GID_NUMBER in attributes and attributes.get(AD_ATTRIBUTE_GID_NUMBER):
            self.gid = int(attributes.get(AD_ATTRIBUTE_GID_NUMBER)[0])
