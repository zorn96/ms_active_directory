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

import copy

from ldap3.utils.dn import parse_dn
from typing import TYPE_CHECKING, List
if TYPE_CHECKING:
    from ms_active_directory.core.ad_domain import ADDomain


from ms_active_directory.environment.ldap.ldap_constants import (
    AD_ATTRIBUTE_COMMON_NAME,
    AD_ATTRIBUTE_DISPLAY_NAME,
    AD_ATTRIBUTE_GID_NUMBER,
    AD_ATTRIBUTE_GROUP_POLICY_LINK,
    AD_ATTRIBUTE_OBJECT_CLASS,
    AD_ATTRIBUTE_SAMACCOUNT_NAME,
    AD_ATTRIBUTE_UID_NUMBER,
    AD_ATTRIBUTE_UNIX_HOME_DIR,
    AD_ATTRIBUTE_UNIX_LOGIN_SHELL,
    COMPUTER_OBJECT_CLASS,
    DOMAIN_OBJECT_CLASS,
    GROUP_OBJECT_CLASS,
    GROUP_POLICY_CONTAINER_CLASS,
    ORGANIZATIONAL_UNIT_OBJECT_CLASS,
    POSIX_GROUP_OBJECT_CLASS,
    POSIX_USER_OBJECT_CLASS,
    USER_OBJECT_CLASS,
    UNKNOWN_GROUP_POSIX_GID,
    UNKNOWN_USER_POSIX_UID,
)


def cast_ad_object_to_specific_object_type(ad_obj: 'ADObject'):
    """ Given an AD Object, find a more specific subclass for it and cast it. """
    obj_type = None
    if ad_obj.is_of_object_class(COMPUTER_OBJECT_CLASS):  # computers are also users so check this first
        obj_type = ADComputer
    elif ad_obj.is_of_object_class(USER_OBJECT_CLASS):
        obj_type = ADUser
        if ad_obj.is_of_object_class(POSIX_USER_OBJECT_CLASS):
            obj_type = ADPosixUser
    elif ad_obj.is_of_object_class(GROUP_OBJECT_CLASS):
        obj_type = ADGroup
        if ad_obj.is_of_object_class(POSIX_GROUP_OBJECT_CLASS):
            obj_type = ADPosixGroup
    elif ad_obj.is_of_object_class(ORGANIZATIONAL_UNIT_OBJECT_CLASS):
        obj_type = ADOrganizationalUnit
    elif ad_obj.is_of_object_class(DOMAIN_OBJECT_CLASS):
        obj_type = ADDomainContainerObject
    elif ad_obj.is_of_object_class(GROUP_POLICY_CONTAINER_CLASS):
        obj_type = ADGroupPolicy

    # return as is if we can't find anything more specific
    if not obj_type:
        return ad_obj
    return obj_type(ad_obj.distinguished_name, ad_obj.all_attributes, ad_obj.domain)


def parse_gplink_to_dn_list(group_policy_links_str: str) -> List[str]:
    """ Given a gpLink attribute string, convert it to a list of policy distinguished names """
    # format is a stringified list. for example
    # '[LDAP://CN={6AC1786C-016F-11D2-945F-00C04fB984F9},CN=Policies,CN=System,DC=AZ,DC=LOCAL;0]'
    # so split on "[LDAP://"s and remove the trailing ;0] for each policy
    group_policy_link_dns = group_policy_links_str.split('[LDAP://')
    # we split on [LDAP:// because ;s could be in DNs. but we'll need to remove trailing ;0]s at the ends
    filtered_trimmed_dns = []
    for policy in group_policy_link_dns:
        if not policy:
            continue
        if policy.endswith(';0]'):
            policy = policy[:-3]
        filtered_trimmed_dns.append(policy)
    return filtered_trimmed_dns


# the parent of all ADObjects, defined here to avoid risk of circular imports

class ADObject:

    def __init__(self, dn: str, attributes: dict, domain: 'ADDomain'):
        self.distinguished_name = dn
        self.domain = domain
        self.all_attributes = attributes if attributes else {}
        self.object_classes = attributes.get(AD_ATTRIBUTE_OBJECT_CLASS)
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
        # remove trailing comma for a proper RDN
        if self.location.endswith(','):
            self.location = self.location[:-1]

        # find any policies attached to the object if we have the right attributes
        self.attached_policies = None
        if AD_ATTRIBUTE_GROUP_POLICY_LINK in attributes and attributes.get(AD_ATTRIBUTE_GROUP_POLICY_LINK):
            self.attached_policies = parse_gplink_to_dn_list(attributes.get(AD_ATTRIBUTE_GROUP_POLICY_LINK))

    def get(self, attribute_name: str, unpack_one_item_lists=False):
        """ Get an attribute about the group that isn't explicitly tracked as a member """
        val = self.all_attributes.get(attribute_name)
        # there's a lot of 1-item lists from the ldap3 library
        if isinstance(val, list) and len(val) == 1 and unpack_one_item_lists:
            return copy.deepcopy(val[0])
        return copy.deepcopy(val)

    def is_of_object_class(self, obj_cls: str) -> bool:
        """ Returns true if this object has the specified object class as one of its object classes. """
        if (not obj_cls) or (not self.object_classes):
            return False
        obj_cls = obj_cls.lower()
        return obj_cls in [o_cls.lower() for o_cls in self.object_classes]

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


class ADDomainContainerObject(ADObject):

    def __init__(self, dn: str, attributes: dict, domain: 'ADDomain'):
        super().__init__(dn, attributes, domain)
        # used for __repr__
        self.class_name = 'ADDomainContainerObject'


class ADOrganizationalUnit(ADObject):

    def __init__(self, dn: str, attributes: dict, domain: 'ADDomain'):
        super().__init__(dn, attributes, domain)
        # used for __repr__
        self.class_name = 'ADOrganizationalUnit'


class ADGroupPolicy(ADObject):

    def __init__(self, dn: str, attributes: dict, domain: 'ADDomain'):
        super().__init__(dn, attributes, domain)
        # used for __repr__
        self.class_name = 'ADGroupPolicy'
        if AD_ATTRIBUTE_DISPLAY_NAME in attributes and attributes.get(AD_ATTRIBUTE_DISPLAY_NAME):
            self.name = attributes.get(AD_ATTRIBUTE_DISPLAY_NAME)
