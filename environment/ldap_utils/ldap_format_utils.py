
from ldap3.core.exceptions import LDAPInvalidDnError
from ldap3.utils.dn import parse_dn

from environment.ldap_utils.ldap_constants import (
    AD_USERNAME_RESTRICTED_CHARS,
    SAM_ACCOUNT_NAME_LENGTH,
    LEGACY_SAM_ACCOUNT_NAME_LENGTH_LIMIT,
)


def is_dn(anything):
    """ Determine if a specified string is a distinguished name. """
    try:
        parse_dn(anything)
        return True
    except LDAPInvalidDnError:
        return False


def construct_default_hostnames_for_computer(computer_name, domain_dns_name):
    """ Construct the default hostnames for a computer in AD. The short hostname is the computer name capitalized,
    and the fqdn is lowercase of the computer name dot the domain.
    """
    return [computer_name.upper(), computer_name.lower() + '.' + domain_dns_name.lower()]


def construct_object_distinguished_name(object_name, object_location, domain):
    """
    Constructs the distinguished name of a computer, group, or user given the name, join location, and domain.
    """
    computer_part = 'CN=' + object_name
    domain_part = construct_ldap_base_dn_from_domain(domain)
    return ','.join([computer_part, object_location, domain_part])


def construct_domain_from_ldap_base_dn(domain):
    """
    Given a base DN, constructs the DNS name of the AD domain.
    """
    dn_split = parse_dn(domain)
    # parse dn takes "cn=demo,ou=Computers,dc=example,DC=com" and turns it into
    # [('cn', 'demo', ','), ('ou', 'Computers', ','), ('dc', 'example', ','), ('DC', 'com', '')]
    domain_pieces = [piece[1] for piece in dn_split if piece[0].upper() == 'DC']
    return '.'.join(domain_pieces)


def construct_ldap_base_dn_from_domain(domain):
    """
    Given a domain, constructs the base dn.
    """
    domain_split = domain.split('.')
    return ','.join(map(lambda x: 'DC=' + x, domain_split))


def construct_service_principal_names(services, hostnames):
    """ Given a list of services and hostnames, construct the kerberos server principle names for them. """
    spns = []
    for serv in services:
        for hostname in hostnames:
            spns.append(serv + '/' + hostname)
    return spns


def escape_generic_filter_value(anything):
    """ Escape anything, so that it can be used in ldap queries without confusing the server.
    According to the LDAP spec, there's a set of common characters that need escaping:
    rfc4514 (https://tools.ietf.org/html/rfc4514).

    RFCs that define new LDAP attributes, as well different server types, may require
    additional characters be escaped. Additionally, not all characters need to be escaped.
    For example, many versions of AD do not require commas be escaped, but will be ok if
    they are. Please ensure you know what you're escaping before calling this.
    See escape_dn_for_filter for an example of an alternative escape function needed to
    escape a field with different properties.
    """
    if anything.isalnum():
        return anything

    def escape_char(char):
        """ Escape a single character."""
        if char in "*()\\/\0 \t\r\n+<>,\";":
            # LDAP query language is really forgiving about strange characters.
            # rfc2254 says the only characters to escape are "*{}\\\0". AD adds "/" to the
            # list, and OpenLDAP adds whitespace. Over-escaping is safe, so just do everything
            # every time.
            return "\\%02x" % ord(char)
        else:
            return char
    return "".join(escape_char(x) for x in anything)


def escape_dn_for_filter(anything):
    """Escape an LDAP distinguished name so that it can be used in filters without confusing the server.
    Distinguished names already have some special characters escaped or encoded, so we must use this
    function instead of the generic escape function, which would escape the existing escape sequences.

    In a filter, you use the format field=value.
    But distinguished names are in the form CN=x,OU=y,DC=z so those equal signs need to be escaped.
    But then the values x, y, and z can also have equal signs in them, and those will ALREADY be escaped
    differently from the ones following CN, OU, etc.
    That's why DNs need a different escaping in filters than everything else.
    """
    if anything.isalnum():
        return anything

    def escape_char(char):
        """ Escape a single character."""
        if char in "()*":
            return "\\%02x" % ord(char)
        else:
            return char
    return "".join(escape_char(x) for x in anything)


def normalize_object_location_in_domain(location, domain_dns_name):
    """ There's two main formats we might see used for an object location - LDAP style and Windows Path style.
    For each style, they can be relative or fully qualified.

    LDAP Style looks like this:
    OU=Location
    or fully qualified:
    OU=Location,DC=example,DC=com

    Windows Path Style looks like this:
    computers/
    or fully qualified:
    example.com/computers

    This function tries to normalize everything to the LDAP style using the relative DN format, since the library
    is primarily LDAP based.
    Currently, windows path style will be rejected. This is because we'd need to make LDAP queries at each level
    to determine the proper naming attribute for the next level (e.g. CN or OU). We can do that, but we'd need a
    connection already established or credentials.
    """
    # TODO: make windows path style names work
    if not is_dn(location):
        raise NotImplementedError('Windows-style paths are not supported')
    return strip_domain_from_object_location(location, domain_dns_name)


def strip_domain_from_object_location(location, domain_dns_name):
    """ Our object Location in a domain should be a relative distinguished name (RDN), but if someone specifies the full
    path, let's be forgiving.
    This is a normalizing function to convert to RDNs.
    So if a user specifies "OU=Location,DC=example,DC=com" this function will strip off "DC=example,DC=com"
    and leave the relative distinguished name "OU=Location" which is what we'll actually use.
    """
    if location is None:
        return location

    # cast everything to uppercase in order to avoid worrying about how a customer chose to type their DN.
    # place a comma in front of the domain RDN so that any stripping we do will strip the trailing comma
    domain_rdn_upper = ',' + construct_ldap_base_dn_from_domain(domain_dns_name).upper()
    location = location.upper()
    if location.endswith(domain_rdn_upper):
        trim_length = len(domain_rdn_upper)
        # trim the length of our domain RDN from the end
        location = location[:-trim_length]

    return location


def validate_and_normalize_computer_name(name, supports_legacy_behavior):
    """ Computer common names are sAMAccountNames without the $ at the end. So check for allowable
    characters and length limits.
    """
    limit = LEGACY_SAM_ACCOUNT_NAME_LENGTH_LIMIT if supports_legacy_behavior else SAM_ACCOUNT_NAME_LENGTH
    # peel off the ending $ if present
    if name.endswith('$'):
        name = name[:-1]
    if len(name) > limit:
        raise Exception('Computer name length must be fewer than {} characters for computers that {} legacy behavior.'
                        .format(limit, 'support' if supports_legacy_behavior else 'do not support'))
    for character in AD_USERNAME_RESTRICTED_CHARS:
        if character in name:
            raise Exception('AD computer names may not contain any of the following characters: {}'
                            .format(', '.join(AD_USERNAME_RESTRICTED_CHARS)))
    return name
