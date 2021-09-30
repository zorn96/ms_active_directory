Exceptions
##########

The following exception types have been created for this library.
If you wish to create a catch-all try/except then you can use **MsActiveDirectoryException**,
as it's the parent exception for all others.


``class MsActiveDirectoryException(Exception):``
    """ A parent class for all other exceptions so that users can have a catch-all exception for
    functional issues that still doesn't blind them to things like accidentally providing a string
    where a number is needed.
    """


``class AttributeModificationException(MsActiveDirectoryException):``
    """ An exception raised when an error is encountered modifying attributes of users, groups, etc. """



``class DomainConnectException(MsActiveDirectoryException):``
    """ An exception raised when an error is encountered connecting to an AD Domain """



``class DomainJoinException(MsActiveDirectoryException):``
    """ An exception raised when an error is encountered joining to an AD Domain or validating the join """



``class DomainSearchException(MsActiveDirectoryException):``
    """ An exception raised when an error is encountered searching an AD Domain """



``class DuplicateNameException(MsActiveDirectoryException):``
    """ An exception raised when multiple records are found during an operation that expects to operate on a
    unique object
    """



``class InvalidComputerParameterException(MsActiveDirectoryException):``
    """ An exception raised when functions are called on a ManagedADComputer object with invalid
    parameters or that rely on unpopulated attributes.
    """



``class InvalidDomainParameterException(MsActiveDirectoryException):``
    """ An exception raised when invalid parameters are used for creating a domain object or
    establishing a connection with a domain.
    """



``class InvalidLdapParameterException(MsActiveDirectoryException):``
    """ An exception raised when a parameter specified is not of a proper type or format to
    convert to an LDAP attribute as needed for a function.
    """



``class KeytabEncodingException(MsActiveDirectoryException):``
    """ An exception raised when a keytab is read in from a file but the encoding is invalid """



``class LdapResponseDecodeException(MsActiveDirectoryException):``
    """ An exception raised when an LDAP response cannot be parsed properly """



``class MembershipModificationException(MsActiveDirectoryException):``
    """ An exception raised when an error is encountered modifying group memberships, and rollback
    of the incomplete changes was successful.
    """



``class MembershipModificationRollbackException(MsActiveDirectoryException):``
    """ An exception raised when an error is encountered modifying group memberships, but rollback
    of the incomplete changes was unsuccessful.
    """



``class ObjectCreationException(MsActiveDirectoryException):``
    """ An exception raised when an error is encountered creating an object """



``class ObjectNotFoundException(MsActiveDirectoryException):``
    """ An exception raised when an object cannot be found when performing validation that an object
    exists as part of a function.
    """



``class PermissionDeniedException(MsActiveDirectoryException):``
    """ An exception raised when permission errors occur operating within AD """



``class SecurityDescriptorDecodeException(MsActiveDirectoryException):``
    """ An exception raised when errors occur decoding a security descriptor """



``class SecurityDescriptorEncodeException(MsActiveDirectoryException):``
    """ An exception raised when errors occur encoding a security descriptor """



``class SessionTransferException(MsActiveDirectoryException):``
    """ An exception raised when errors occur transferring an authentication session from
    one domain to another
    """



``class TrustedDomainConversionException(MsActiveDirectoryException):``
    """ An exception raised when trying to convert a trusted domain that has a non-AD type
    to an ADDomain
    """

