""" Exceptions used within the library """
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


class MsActiveDirectoryException(Exception):
    """ A parent class for all other exceptions so that users can have a catch-all exception for
    functional issues that still doesn't blind them to things like accidentally providing a string
    where a number is needed.
    """
    def __init__(self, exception_str):
        self.message = exception_str
        super().__init__(self.message)


class AttributeModificationException(MsActiveDirectoryException):
    """ An exception raised when an error is encountered modifying attributes of users, groups, etc. """
    def __init__(self, exception_str):
        super().__init__(exception_str)


class DomainConnectException(MsActiveDirectoryException):
    """ An exception raised when an error is encountered connecting to an AD Domain """
    def __init__(self, exception_str):
        super().__init__(exception_str)


class DomainJoinException(MsActiveDirectoryException):
    """ An exception raised when an error is encountered joining to an AD Domain or validating the join """
    def __init__(self, exception_str):
        super().__init__(exception_str)


class DomainSearchException(MsActiveDirectoryException):
    """ An exception raised when an error is encountered searching an AD Domain """
    def __init__(self, exception_str):
        super().__init__(exception_str)


class DuplicateNameException(MsActiveDirectoryException):
    """ An exception raised when multiple records are found during an operation that expects to operate on a
    unique object
    """
    def __init__(self, exception_str):
        super().__init__(exception_str)


class InvalidComputerParameterException(MsActiveDirectoryException):
    """ An exception raised when functions are called on a ManagedADComputer object with invalid
    parameters or that rely on unpopulated attributes.
    """
    def __init__(self, exception_str):
        super().__init__(exception_str)


class InvalidDomainParameterException(MsActiveDirectoryException):
    """ An exception raised when invalid parameters are used for creating a domain object or
    establishing a connection with a domain.
    """
    def __init__(self, exception_str):
        super().__init__(exception_str)


class InvalidLdapParameterException(MsActiveDirectoryException):
    """ An exception raised when a parameter specified is not of a proper type or format to
    convert to an LDAP attribute as needed for a function.
    """
    def __init__(self, exception_str):
        super().__init__(exception_str)


class KeytabEncodingException(MsActiveDirectoryException):
    """ An exception raised when a keytab is read in from a file but the encoding is invalid """
    def __init__(self, exception_str):
        super().__init__(exception_str)


class LdapResponseDecodeException(MsActiveDirectoryException):
    """ An exception raised when an LDAP response cannot be parsed properly """
    def __init__(self, exception_str):
        super().__init__(exception_str)


class MembershipModificationException(MsActiveDirectoryException):
    """ An exception raised when an error is encountered modifying group memberships, and rollback
    of the incomplete changes was successful.
    """
    def __init__(self, exception_str):
        super().__init__(exception_str)


class MembershipModificationRollbackException(MsActiveDirectoryException):
    """ An exception raised when an error is encountered modifying group memberships, but rollback
    of the incomplete changes was unsuccessful.
    """
    def __init__(self, exception_str):
        super().__init__(exception_str)


class ObjectCreationException(MsActiveDirectoryException):
    """ An exception raised when an error is encountered creating an object """
    def __init__(self, exception_str):
        super().__init__(exception_str)


class ObjectNotFoundException(MsActiveDirectoryException):
    """ An exception raised when an object cannot be found when performing validation that an object
    exists as part of a function.
    """
    def __init__(self, exception_str):
        super().__init__(exception_str)


class PermissionDeniedException(MsActiveDirectoryException):
    """ An exception raised when permission errors occur operating within AD """
    def __init__(self, exception_str):
        super().__init__(exception_str)


class SecurityDescriptorDecodeException(MsActiveDirectoryException):
    """ An exception raised when errors occur decoding a security descriptor """
    def __init__(self, exception_str):
        super().__init__(exception_str)


class SecurityDescriptorEncodeException(MsActiveDirectoryException):
    """ An exception raised when errors occur encoding a security descriptor """
    def __init__(self, exception_str):
        super().__init__(exception_str)


class SessionTransferException(MsActiveDirectoryException):
    """ An exception raised when errors occur transferring an authentication session from
    one domain to another
    """
    def __init__(self, exception_str):
        super().__init__(exception_str)


class TrustedDomainConversionException(MsActiveDirectoryException):
    """ An exception raised when trying to convert a trusted domain that has a non-AD type
    to an ADDomain
    """
    def __init__(self, exception_str):
        super().__init__(exception_str)
