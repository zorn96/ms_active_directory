""" Exceptions used within the library """


class MsActiveDirectoryException(Exception):
    """ A parent class for all other exceptions so that users can have a catch-all exception for
    functional issues that still doesn't blind them to things like accidentally providing a string
    where a number is needed.
    """
    def __init__(self, exception_str):
        self.message = exception_str
        super().__init__(self.message)


class AttributeModificationException(MsActiveDirectoryException):
    def __init__(self, exception_str):
        super().__init__(exception_str)


class DomainConnectException(MsActiveDirectoryException):
    def __init__(self, exception_str):
        super().__init__(exception_str)


class DomainJoinException(MsActiveDirectoryException):
    def __init__(self, exception_str):
        super().__init__(exception_str)


class DomainSearchException(MsActiveDirectoryException):
    def __init__(self, exception_str):
        super().__init__(exception_str)


class DuplicateNameException(MsActiveDirectoryException):
    def __init__(self, exception_str):
        super().__init__(exception_str)


class InformationUnavailableException(MsActiveDirectoryException):
    def __init__(self, exception_str):
        super().__init__(exception_str)


class InvalidComputerParameterException(MsActiveDirectoryException):
    def __init__(self, exception_str):
        super().__init__(exception_str)


class InvalidDomainParameterException(MsActiveDirectoryException):
    def __init__(self, exception_str):
        super().__init__(exception_str)


class InvalidLdapParameterException(MsActiveDirectoryException):
    def __init__(self, exception_str):
        super().__init__(exception_str)


class KeytabEncodingException(MsActiveDirectoryException):
    def __init__(self, exception_str):
        super().__init__(exception_str)


class LdapResponseDecodeException(MsActiveDirectoryException):
    def __init__(self, exception_str):
        super().__init__(exception_str)


class MembershipModificationException(MsActiveDirectoryException):
    def __init__(self, exception_str):
        super().__init__(exception_str)


class MembershipModificationRollbackException(MsActiveDirectoryException):
    def __init__(self, exception_str):
        super().__init__(exception_str)


class ObjectCreationException(MsActiveDirectoryException):
    def __init__(self, exception_str):
        super().__init__(exception_str)


class ObjectNotFoundException(MsActiveDirectoryException):
    def __init__(self, exception_str):
        super().__init__(exception_str)


class PermissionDeniedException(MsActiveDirectoryException):
    def __init__(self, exception_str):
        super().__init__(exception_str)


class SecurityDescriptorDecodeException(MsActiveDirectoryException):
    def __init__(self, exception_str):
        super().__init__(exception_str)


class SecurityDescriptorEncodeException(MsActiveDirectoryException):
    def __init__(self, exception_str):
        super().__init__(exception_str)


class TrustedDomainConversionException(MsActiveDirectoryException):
    def __init__(self, exception_str):
        super().__init__(exception_str)
