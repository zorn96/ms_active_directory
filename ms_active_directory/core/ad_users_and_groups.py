
from ms_active_directory.environment.ldap.ldap_constants import (
    AD_ATTRIBUTE_COMMON_NAME,
    AD_ATTRIBUTE_OBJECT_CLASS,
    AD_ATTRIBUTE_SAMACCOUNT_NAME
)
from ms_active_directory.environment.ldap.ldap_format_utils import (
    normalize_object_location_in_domain
)


class ADUser:

    def __init__(self, dn: str, attributes: dict, domain):
        self.distinguished_name = dn
        self.domain = domain
        self.samaccount_name = attributes.get(AD_ATTRIBUTE_SAMACCOUNT_NAME)
        self.common_name = attributes.get(AD_ATTRIBUTE_COMMON_NAME)
        self.object_classes = attributes.get(AD_ATTRIBUTE_OBJECT_CLASS)
        self.name = self.samaccount_name
        # to get the location of a user, remove their common name from the front and the domain's
        # domain components from the end
        rdn_of_user = normalize_object_location_in_domain(dn, self.domain.get_domain_dns_name())
        user_piece = 'CN=' + self.common_name
        self.location = rdn_of_user[len(user_piece)+1:]
        self.other_attributes = attributes

    def get(self, attribute_name: str):
        """ Get an attribute about the group that isn't explicitly tracked as a member """
        val = self.other_attributes.get(attribute_name)
        # there's a lot of 1-item lists from the ldap3 library
        if isinstance(val, list) and len(val) == 1:
            return val[0]
        return val


class ADGroup:

    def __init__(self, dn: str, attributes: dict, domain):
        self.distinguished_name = dn
        self.domain = domain
        self.samaccount_name = attributes.get(AD_ATTRIBUTE_SAMACCOUNT_NAME)
        self.common_name = attributes.get(AD_ATTRIBUTE_COMMON_NAME)
        self.object_classes = attributes.get(AD_ATTRIBUTE_OBJECT_CLASS)
        self.name = self.samaccount_name
        # to get the location of a user, remove their common name from the front and the domain's
        # domain components from the end
        rdn_of_user = normalize_object_location_in_domain(dn, self.domain.get_domain_dns_name())
        user_piece = 'CN=' + self.common_name
        self.location = rdn_of_user[len(user_piece)+1:]
        self.other_attributes = attributes

    def get(self, attribute_name: str):
        """ Get an attribute about the group that isn't explicitly tracked as a member """
        val = self.other_attributes.get(attribute_name)
        # there's a lot of 1-item lists from the ldap3 library
        if isinstance(val, list) and len(val) == 1:
            return val[0]
        return val
