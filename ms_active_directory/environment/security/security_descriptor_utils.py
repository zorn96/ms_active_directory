""" Utilities for encoding and decoding Active Directory Security Descriptors.

An Active Directory Security Descriptor details what different users and groups can and
cannot do on an object.
So rather than users/groups/etc. having a rule on them that says "this entity can do these
things", the security descriptor in a windows model says "this is what other entities can
do to this one."

These utilities are useful for decoding ACLs and ACEs, as well as manipulating them to add
permissions for various users and groups.
"""
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

import binascii
import uuid

from ldap3.protocol.controls import build_control
from pyasn1.type.namedtype import NamedTypes, NamedType
from pyasn1.type.univ import Sequence, Integer
from struct import pack, unpack, calcsize
from six import b
from typing import List

from ms_active_directory.environment.ldap.ldap_format_utils import escape_bytestring_for_filter
from ms_active_directory.environment.security.security_config_constants import (
    ACE_BODY,
    ACE_COUNT,
    ACE_FLAGS,
    ACE_LEN,
    ACE_SIZE,
    ACE_TYPE,
    ACE_TYPE_NAME,
    ACL_REVISION,
    ACL_SIZE,
    AD_SERVER_SECURITY_DESCRIPTOR_FLAGS_OID,
    APPLICATION_DATA,
    CONTROL,
    DACL,
    DATA,
    DATA_LEN,
    FLAGS,
    GROUP_SID,
    IDENTIFIER_AUTHORITY,
    INHERITED_OBJECT_TYPE,
    INHERITED_OBJECT_TYPE_LEN,
    LENGTH_DESCRIPTOR_FMT,
    MASK,
    OBJECT_TYPE,
    OBJECT_TYPE_LEN,
    OFFSET_DACL,
    OFFSET_GROUP,
    OFFSET_OWNER,
    OFFSET_SACL,
    OWNER_SID,
    REVISION,
    SACL,
    SBZ1,
    SBZ2,
    SID,
    SUB_AUTHORITY,
    SUB_AUTHORITY_COUNT,
    SUB_AUTHORITY_LEN,
    VALUE,
)
from ms_active_directory.exceptions import (
    SecurityDescriptorDecodeException,
    SecurityDescriptorEncodeException
)


def add_permissions_to_security_descriptor_dacl(current_security_descriptor_bytes: bytes, sid_string: str,
                                                access_masks: List['AccessMask'] = None,
                                                privilege_guids: List[str] = None,
                                                read_property_guids: List[str] = None,
                                                write_property_guids: List[str] = None):
    """ Given a bytestring for the current security descriptor on an Active Directory object,
    an SID to add permissions for, an optional list of access masks, and an optional list of
    privilege guids, we construct new ACE entries for every access mask and privilege guid we
    want to add.
    We then add these ACEs to the DACL of the security descriptor and compute the new security
    descriptor.

    This function works even if we're adding access masks and privilege guids that already exist
    for the on the object for the given SID. Active Directory will de-dupe the ACEs and collapse
    them down.
    """
    current_sd = SelfRelativeSecurityDescriptor()
    current_sd.parse_structure_from_bytes(current_security_descriptor_bytes)
    current_sd = add_permissions_to_security_descriptor(current_sd, sid_string, access_masks, privilege_guids,
                                                        read_property_guids, write_property_guids)

    return current_sd.get_data(force_recompute=True)


def add_permissions_to_security_descriptor(current_security_descriptor, sid_string: str,
                                           access_masks: List['AccessMask'] = None, privilege_guids: List[str] = None,
                                           read_property_guids: List[str] = None,
                                           write_property_guids: List[str] = None):
    """ Given a security descriptor object representing the DACL bytes on an Active Directory object,
    an SID to add permissions for, an optional list of access masks, and an optional list of
    privilege guids, we construct new ACE entries for every access mask and privilege guid we
    want to add.
    We then add these ACEs to the DACL of the security descriptor and compute the new security
    descriptor.

    This function works even if we're adding access masks and privilege guids that already exist
    for the on the object for the given SID. Active Directory will de-dupe the ACEs and collapse
    them down.
    """
    new_aces = []
    access_masks = access_masks if access_masks is not None else []
    for a_mask in access_masks:
        new_ace = create_ace_for_allow_access(sid_string, a_mask)
        new_aces.append(new_ace)

    guid_access_type_tuples = []
    if privilege_guids:
        guid_access_type_tuples.extend([(guid, AccessAllowedObjectAce.ADS_RIGHT_DS_CONTROL_ACCESS)
                                        for guid in privilege_guids])
    if read_property_guids:
        guid_access_type_tuples.extend([(guid, AccessAllowedObjectAce.ADS_RIGHT_DS_READ_PROP)
                                        for guid in read_property_guids])
    if write_property_guids:
        guid_access_type_tuples.extend([(guid, AccessAllowedObjectAce.ADS_RIGHT_DS_WRITE_PROP)
                                        for guid in write_property_guids])
    for guid, access_type in guid_access_type_tuples:
        new_ace = create_ace_for_allow_object_operation_or_property_access(sid_string, guid, access_type)
        new_aces.append(new_ace)

    if not new_aces:
        return current_security_descriptor

    current_security_descriptor[DACL].append_aces(new_aces)

    return current_security_descriptor


def create_ace_for_allow_access(sid_string: str, access_mask: 'AccessMask'):
    """ Construct an Access Control Entry (ACE) granting the provided SID the provided permission
    on the object to which the ACE is attached.
    """
    new_ace = ACE()
    new_ace[ACE_TYPE] = AccessAllowedAce.ACE_TYPE
    # If we're building an ACE from scratch, it's not inherited. We're not propagating this to any
    # children either, since we're not creating children and if we do they'd be explicitly
    # managed.
    # These ACE flags are about inheritance, so since we're not doing any, set them to 0.
    new_ace[ACE_FLAGS] = 0x00

    # Construct our mask according to the thing we're being granted access for.
    acedata = AccessAllowedAce()
    acedata[MASK] = AccessMask()
    acedata[MASK][MASK] = access_mask

    # construct the sid entry for whatever is getting this access
    acedata[SID] = ObjectSid()
    acedata[SID].from_canonical_string_format(sid_string)

    new_ace[ACE_BODY] = acedata
    return new_ace


def create_ace_for_allow_object_operation_or_property_access(sid_string, privilege_or_property_guid, access_type):
    """ Construct an Access Control Entry (ACE) granting the provided SID control access to a
    specific sub-privilege within the object control area of the object to which the ACE is
    attached.
    """
    new_ace = ACE()
    new_ace[ACE_TYPE] = AccessAllowedObjectAce.ACE_TYPE
    # If we're building an ACE from scratch, it's not inherited. We're not propagating this to any
    # children either, since we're not creating children and if we do they'd be explicitly
    # managed.
    # These ACE flags are about inheritance, so since we're not doing any, set them to 0.
    new_ace[ACE_FLAGS] = 0x00

    ace_data = AccessAllowedObjectAce()
    # grant ourselves the appropriate mask based on our access type. this could be invoking a privileged operation,
    # or reading/writing a property
    ace_data[MASK] = AccessMask()
    ace_data[MASK][MASK] = access_type

    # set our object type to our privilege or property guid, since that is the "object" we're getting
    # access to. we need to convert our guid string to a UUID and get the bytes in little-endian
    # format.
    ace_data[OBJECT_TYPE] = uuid.UUID(privilege_or_property_guid).bytes_le
    # no inherited object type
    ace_data[INHERITED_OBJECT_TYPE] = b''

    # construct the sid entry for whatever is getting this access
    ace_data[SID] = ObjectSid()
    ace_data[SID].from_canonical_string_format(sid_string)
    ace_data[FLAGS] = AccessAllowedObjectAce.ACE_OBJECT_TYPE_PRESENT

    new_ace[ACE_BODY] = ace_data
    return new_ace


def get_security_descriptor_read_controls(read_sacl=False):
    """ Get the LDAP query control needed to read a security descriptor, which contains a record's
    rights and permissions, including its self-operation rights and the rights of others to act
    upon it.
    If read_sacl is True, we'll build a control that will try to read both the system ACL (SACL),
    which includes information about how actions are audited and tracked in the AD event log, as
    well as the discretionary ACL (DACL), which just says who can do what to the object.
    Otherwise, we just try to read the discretionary ACL.

    Reading the SACL is much more privileged than the DACL, so the default is to only read our DACL.
    """
    sd_flags = 0x04 if read_sacl else 0x07
    sd_control = SecurityDescriptorFlags()
    sd_control.setComponentByName(FLAGS, sd_flags)
    controls = [build_control(AD_SERVER_SECURITY_DESCRIPTOR_FLAGS_OID, True, sd_control)]
    return controls


class SecurityDescriptorFlags(Sequence):
    """ This is just a class for holding LDAP controls. Ansible has some nice utilities for this,
    with plenty of examples, and it's well maintained. So this is likely better than completely
    writing a LDAP control container from scratch.
    """
    # SDFlagsRequestValue ::= SEQUENCE {
    #     Flags    INTEGER
    # }
    componentType = NamedTypes(NamedType('Flags', Integer()))


class Structure(object):
    """ This class is intended as an extension to python's built in structs which allows its
    sub-classes to define any structure that can be decoded from bytes or turned into bytes
    using pack and unpack the way you would with structs.
    It doesn't inherit the struct class because that seemed annoying to deal with, especially
    since python 3 has breaking changes across a few versions that this library supports.

    A structure is defined by either a field name and a format specification, or by a field name
    and another class that represents the field.
    The latter is used when the value of the field name is complex structure, often with other
    nested fields, whereas the former is used when the value of the field is encoded fairly simply
    as bytes with a single specification of the format.

    The ':' is something of an overloaded operator. It is used as a format specification to indicate
    when a field should just be left as literal bytes (e.g. in "application data"). So it's also used
    in the fields represented by another class to indicate that the literal bytes for the field should
    be supplied to that class in order to decode it.

    Each field can only contain one value.

    We're using string format specifiers instead of booleans or enums mainly to save typing/verbosity.
    There's a lot of combination formats or slight modifications to basic formats (e.g. little endian
    vs. big endian and size of field). So instead of enumerating all of the possible formats as enums,
    which would generate a ton, we use a slightly less readable format to reduce the number of unique
    data types.
    Most of these are based off of the format specifiers used by the python struct library. But there's
    some extras.

    Here's the format specifiers:
        - Any specifiers in struct can be used with the same format and they'll pass right through.
          See struct docs (pack/unpack is eventually called directly if these exist in a format spec).
        - <       [little endian]
        - >       [big endian]
        - c       [character]
        - B       [unsigned byte]
        - H       [unsigned short]
        - L       [unsigned long]
        - s       [string (array of chars)]
                  Using a string is very similar to the kerberos key encoding/decoding - in that, because
                  of the variable length nature of strings, any string must be preceded by a numeric length
                  in the format specifier, and must be padded with zeros as needed to fit into that length
                  of bytes.
                  This is basically only used for SID decoding. And it's only needed for that because things
                  like well-known SIDs have different lengths from domain SIDs.
    some additional format specifiers:
        - :       Just copy the bytes from the field into the output string
                  (input may be string, other structure, or anything responding to __str__())
        - ?-field Length of field named 'field', formatted as specified with ?
                  ('?' may be '!H' for example). The input value overrides the real length.
        - "xxxx   Literal xxxx (field's value doesn't change the output. quotes must not be closed
                  or escaped).
        - _       Will not pack the field. Accepts a third argument, which is an unpack code.
        - ?=code  Evaluate code in the context of the structure, and pack the result as
                  specified by ?
    """
    structure = ()
    REPR_NAME = 'Structure'

    def __init__(self, data: bytes = None, parent_structure: 'Structure' = None):
        self.fields = {}
        self.raw_data = data
        self.parent_structure = parent_structure
        if data is not None:
            self.parse_structure_from_bytes(data)
        else:
            self.data = None

    def get_data(self, force_recompute: bool = False):
        """ If we've ever computed and packed our data before, and not changed since then, return
        that.
        Otherwise, iterate through our structure, pack each field, and return that data.
        """
        if self.data is not None and not force_recompute:
            return self.data

        # pack each field that we have one at a time and use them to build our data.
        # ordering of fields matters, so we use self.structure instead of our fields
        # dictionary since it's ordered
        data = bytes()
        for field in self.structure:
            try:
                data += self.pack_field(field[0], field[1])
            except Exception as e:
                if field[0] in self.fields:
                    e.args += ("When packing field '%s | %s | %r' in %s" %
                               (field[0], field[1], self[field[0]], self.__class__),)
                else:
                    e.args += ("When packing field '%s | %s' in %s" %
                               (field[0], field[1], self.__class__),)
                raise
        self.data = data
        return data

    def get_field_format_spec(self, field_name: str):
        """ Get the format string in our structure for a given field. """
        for field in self.structure:
            if field[0] == field_name:
                return field[1]
        raise SecurityDescriptorDecodeException("Field %s not found" % field_name)

    def find_length_field_for_other_field(self, field_name: str):
        """ Given a field with a spec that may override the real length of the field using another
        field, get the name of the field that overrides the value.
        If the spec doesn't have an override field, this will return None.
        """
        return self.find_override_descriptor_for_field(field_name, LENGTH_DESCRIPTOR_FMT)

    def find_override_descriptor_for_field(self, field_name: str, descriptor_fmt: str):
        """ Given a field with a spec that may override some attribute of the field using another
        field, get the name of the field that overrides the value.
        If the spec doesn't have an override field, this will return None.
        """
        descriptor = descriptor_fmt % field_name
        for field in self.structure:
            if field[1].endswith(descriptor):
                return field[0]
        return None

    def calc_pack_size_for_field(self, field_name: str, format_spec: str = None):
        """ Calculate the size needed to pack the value in the given field. """
        if format_spec is None:
            format_spec = self.get_field_format_spec(field_name)

        return self.calc_pack_or_unpack_size(format_spec, self[field_name])

    def calc_pack_or_unpack_size(self, format_spec: str, data: bytes, field_name: str = None, is_unpack: bool = False):
        """ Calculate the size needed to pack or unpack the given data according to a format
        specification for how the data should be encoded.
        Optionally, the name of the field can be provided. If it is, then we'll check if it has
        an override field, and if so we'll get the value specified in the override field.
        """
        # void specifier on pack or unpack results in 0 size
        if format_spec.startswith('_'):
            return 0

        # On unpack we might have another field that describes how long our field is, but on pack
        # we actually just have to calculate how long the thing we're packing is.
        if is_unpack:
            try:
                length_field = self.find_length_field_for_other_field(field_name)
                if length_field is not None:
                    return int(self[length_field])
            except:
                pass

        # quote specifier
        if format_spec.startswith('"'):
            return len(format_spec) - 1

        # code specifier
        format_split = format_spec.split('=')
        if len(format_split) >= 2:
            return self.calc_pack_or_unpack_size(format_split[0], data, field_name=field_name,
                                                 is_unpack=is_unpack)

        # length specifier
        format_split = format_spec.split('-')
        if len(format_split) == 2:
            return self.calc_pack_or_unpack_size(format_split[0], data, field_name=field_name,
                                                 is_unpack=is_unpack)

        # literal specifier
        if format_spec.startswith(':'):
            return len(data)

        # struct like specifier
        return calcsize(format_spec)

    def pack_field(self, field_name: str, format_spec: str = None):
        """ Pack an individual field's value according to its format specification so we can get
        the bytes for the field.
        """
        # sometimes we can pass the format spec in, removing the need to look it up again. but
        # not always
        if format_spec is None:
            format_spec = self.get_field_format_spec(field_name)

        if field_name in self.fields:
            ans = self.pack(format_spec, self.fields[field_name])
        else:
            ans = self.pack(format_spec, None)

        return ans

    def parse_structure_from_bytes(self, data: bytes):
        """ Given data, unpack it based on the structure we have and build a dictionary mapping
        each field to the appropriately decoded piece of data.
        """
        self.raw_data = data
        for field in self.structure:
            # figure out the size of our field based on its spec
            field_name, format_spec = field[0], field[1]
            size = self.calc_pack_or_unpack_size(format_spec, data, field_name, is_unpack=True)

            # if we have an alternate data class or encoding, grab it
            data_class_or_code = b
            if len(field) > 2:
                data_class_or_code = field[2]

            # unpack our field appropriately and save its value into our fields map
            try:
                self[field_name] = self.unpack(format_spec, data[:size],
                                               data_class_or_code=data_class_or_code)
            except Exception as e:
                e.args += ("When unpacking field '%s | %s | %r[:%d]'" %
                           (field_name, format_spec, data, size),)
                raise

            # calculate the size of the thing we just unpacked and trim that data off of the front
            # of the data passed in.
            size = self.calc_pack_or_unpack_size(format_spec, self[field_name], field_name)
            data = data[size:]

        return self

    def pack(self, format_spec: str, data: bytes):
        """ Given a format specification for encoding data, and the data to encode, pack the data
        into bytes according to our specification.
        """
        # void specifier
        if format_spec.startswith('_'):
            return b''

        # quote specifier
        if format_spec.startswith('"'):
            return b(format_spec[1:])

        # specific encoding specifier
        format_split = format_spec.split('=')
        if len(format_split) >= 2:
            try:
                return self.pack(format_split[0], data)
            except:
                # pack might throw an exception if we what we're trying to pack has a format that
                # actually requires calling some python function. in this case, we use eval to
                # execute the function
                fields = {'self': self}
                fields.update(self.fields)
                return self.pack(format_split[0], eval(format_split[1], {}, fields))

        # fixed length specifier
        format_split = format_spec.split('-')
        if len(format_split) == 2:
            try:
                return self.pack(format_split[0], data)
            except:
                # pack might throw an exception if we try to pack a fixed size of data that's
                # computed rather than literal. if that happens, then we need to use
                # calc_pack_size_for_field, which will itself do the necessary computations,
                # and then pack using that.
                # this will occur when we have a field that is literally just a size, and which is
                # computed from other fields.
                # Example: Ace length is computed using some value multiplied by the number of aces,
                # which is another field. The field that holds ace length is a fixed length field,
                # but the value that goes in there is not based on the data, and instead comes
                # from a computation on the size of the another field.
                return self.pack(format_split[0], self.calc_pack_size_for_field(format_split[1]))

        # once we've gotten past the specifiers that result in literal interpretations of the data
        # to encode, we must have non-null data. null data is ok for things like a void specifier,
        # or when we pass data to another function for evaluation (which can then handle nulls),
        # but it's not ok when we're actually going to encode the data ourselves.
        if data is None:
            raise SecurityDescriptorEncodeException("Trying to pack null value")

        # literal specifier
        if format_spec.startswith(':'):
            if isinstance(data, Structure):
                return data.get_data()
            # If we have an object that can serialize itself, go ahead
            elif hasattr(data, "get_data"):
                return data.get_data()
            elif isinstance(data, int):
                return bytes(data)
            elif isinstance(data, bytes) is not True:
                return bytes(b(data))
            else:
                # what we have is literal bytes at this point
                return data

        # string data
        if format_spec.endswith('s'):
            # Let's be sure we send the right type. Python is stupid.
            if isinstance(data, bytes) or isinstance(data, bytearray):
                return pack(format_spec, data)
            else:
                # thankfully six lets us handle python stupidity by making things bytes-like
                return pack(format_spec, b(data))

        # struct like specifier
        return pack(format_spec, data)

    def unpack(self, format_spec: str, data: bytes, data_class_or_code=b):
        """ Given a format specification, data to unpack, and the class or encoding to use for
        unpacking the data (bytes-like by default), unpack the data according to the format and
        return it.
        """
        # void specifier
        if format_spec.startswith('_'):
            # this doesn't currently get used, but covers an edge case we might have in the future
            # where a field references an object type to construct out of its entire self.
            if data_class_or_code != b:
                fields = {'self': self, 'inputDataLeft': data}
                fields.update(self.fields)
                return eval(data_class_or_code, {}, fields)
            else:
                return None

        # quote specifier
        if format_spec.startswith('"'):
            answer = format_spec[1:]
            # if we're unpacking according to a fixed value specification, the bytes-like version of
            # that needs to match the data
            if b(answer) != data:
                raise SecurityDescriptorDecodeException("Unpacked data doesn't match constant value '{}' should be '{}'"
                                                        .format(data, answer))
            return answer

        # code specifier
        format_split = format_spec.split('=')
        if len(format_split) >= 2:
            return self.unpack(format_split[0], data)

        # length specifier
        format_split = format_spec.split('-')
        if len(format_split) == 2:
            return self.unpack(format_split[0], data)

        # literal specifier
        if format_spec == ':':
            if isinstance(data, bytes) and data_class_or_code is b:
                return data
            return data_class_or_code(data)

        # struct like specifier
        return unpack(format_spec, data)[0]

    def keys(self):
        """ The actual fields of our structure are ordered, so this shouldn't be used for iteration
        in any kind of unpacking/packing of our data. But supporting common dict-like operations
        makes it easier to programmatically check presence or absence of various keys and values
        so we support it.
        """
        return self.fields.keys()

    def values(self):
        """ The actual fields of our structure are ordered, so this shouldn't be used for iteration
        in any kind of unpacking/packing of our data. But supporting common dict-like operations
        makes it easier to programmatically check presence or absence of various keys and values
        so we support it.
        """
        return self.fields.values()

    def items(self):
        """ The actual fields of our structure are ordered, so this shouldn't be used for iteration
        in any kind of unpacking/packing of our data. But supporting common dict-like operations
        makes it easier to programmatically check presence or absence of various keys and values
        so we support it.
        """
        return self.fields.items()

    def reset_data(self):
        self.data = None
        # force our parents to reset their data as well
        if self.parent_structure is not None:
            self.parent_structure.reset_data()

    def __delitem__(self, key: str):
        del self.fields[key]
        # force a recompute the next time someone tries to get data, since things have changed
        self.reset_data()

    def __getitem__(self, key: str):
        return self.fields[key]

    def __setitem__(self, key: str, value):
        self.fields[key] = value
        # force a recompute the next time someone tries to get data, since things have changed
        self.reset_data()

    def __len__(self):
        return len(self.get_data())

    def __str__(self):
        # our data cannot necessarily be encoded as a string, so convert it to hex
        return '0x' + binascii.hexlify(self.get_data()).decode('UTF-8')

    def __eq__(self, other: 'Structure'):
        if not isinstance(other, Structure):
            return False
        return other.get_data() == self.get_data()

    def __hash__(self):
        return self.get_data().__hash__()

    def __repr__(self):
        repres = '{}('.format(self.REPR_NAME)
        data = self.get_data()
        repres += 'data={}'.format(data)
        if self.parent_structure is not None:
            repres += ', parent_structure={}'.format(self.parent_structure.__repr__())
        repres += ')'
        return repres


class LdapSidIdentifierAuthority(Structure):
    """ LDAP SID structure - based on SAMR_RPC_SID, except the SubAuthority is little-endian here.
    Class renamed to match python naming conventions.
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/c6ce4275-3d90-4890-ab3a-514745e4637e
    """
    structure = (
        (VALUE, '6s'),
    )
    REPR_NAME = 'LdapSidIdentifierAuthority'


class ObjectSid(Structure):
    """
    SID as described in 2.4.2
    Class renamed to match python naming conventions.
    https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/78eb9013-1c3a-4970-ad1f-2b1dad588a25
    """
    structure = (
        (REVISION, '<B'),
        (SUB_AUTHORITY_COUNT, '<B'),
        (IDENTIFIER_AUTHORITY, ':', LdapSidIdentifierAuthority),
        (SUB_AUTHORITY_LEN, '_-{}'.format(SUB_AUTHORITY),
         'self["{}"]*4'.format(SUB_AUTHORITY_COUNT)),
        (SUB_AUTHORITY, ':'),
    )
    REPR_NAME = 'ObjectSid'

    def from_canonical_string_format(self, canonical: str):
        items = canonical.split('-')
        self[REVISION] = int(items[1])
        self[IDENTIFIER_AUTHORITY] = LdapSidIdentifierAuthority(parent_structure=self)
        self[IDENTIFIER_AUTHORITY][VALUE] = b'\x00\x00\x00\x00\x00' + pack('B', int(items[2]))
        self[SUB_AUTHORITY_COUNT] = len(items) - 3
        self[SUB_AUTHORITY] = b''
        for i in range(self[SUB_AUTHORITY_COUNT]):
            self[SUB_AUTHORITY] += pack('<L', int(items[i + 3]))

    def to_canonical_string_format(self):
        ans = 'S-%d-%d' % (self[REVISION], ord(self[IDENTIFIER_AUTHORITY][VALUE][5:6]))
        for i in range(self[SUB_AUTHORITY_COUNT]):
            ans += '-%d' % (unpack('<L', self[SUB_AUTHORITY][i * 4:i * 4 + 4])[0])
        return ans

    def to_ldap_filter_string_format(self):
        return escape_bytestring_for_filter(self.get_data())


class SelfRelativeSecurityDescriptor(Structure):
    """
    Self-relative security descriptor as described in 2.4.6
    Class renamed to match python naming conventions.
    https://msdn.microsoft.com/en-us/library/cc230366.aspx
    """
    structure = (
        (REVISION, 'c'),
        (SBZ1, 'c'),
        (CONTROL, '<H'),
        (OFFSET_OWNER, '<L'),
        (OFFSET_GROUP, '<L'),
        (OFFSET_SACL, '<L'),
        (OFFSET_DACL, '<L'),
        (SACL, ':'),
        (DACL, ':'),
        (OWNER_SID, ':'),
        (GROUP_SID, ':'),
    )
    REPR_NAME = 'SelfRelativeSecurityDescriptor'

    def parse_structure_from_bytes(self, data: bytes):
        Structure.parse_structure_from_bytes(self, data)
        # All these fields are optional, if the offset is 0 they are empty
        # there are also flags indicating if they are present
        if self[OFFSET_OWNER] != 0:
            self[OWNER_SID] = ObjectSid(data=data[self[OFFSET_OWNER]:], parent_structure=self)
        else:
            self[OWNER_SID] = b''

        if self[OFFSET_GROUP] != 0:
            self[GROUP_SID] = ObjectSid(data=data[self[OFFSET_GROUP]:], parent_structure=self)
        else:
            self[GROUP_SID] = b''

        if self[OFFSET_SACL] != 0:
            self[SACL] = ACL(data=data[self[OFFSET_SACL]:], parent_structure=self)
        else:
            self[SACL] = b''

        if self[OFFSET_DACL] != 0:
            self[DACL] = ACL(data=data[self[OFFSET_DACL]:], parent_structure=self)
        else:
            self[DACL] = b''

    def get_data(self, force_recompute: bool = False):
        headerlen = 20
        # Reconstruct the security descriptor
        # flags are currently not set automatically, so if we changed a top level flag around
        # inheritance propagation/breaking, the caller that's doing so must set the flags manually
        datalen = 0
        if self[SACL] != b'':
            self[OFFSET_SACL] = headerlen + datalen
            datalen += len(self[SACL].get_data(force_recompute=force_recompute))
        else:
            self[OFFSET_SACL] = 0

        if self[DACL] != b'':
            self[OFFSET_DACL] = headerlen + datalen
            datalen += len(self[DACL].get_data(force_recompute=force_recompute))
        else:
            self[OFFSET_DACL] = 0

        if self[OWNER_SID] != b'':
            self[OFFSET_OWNER] = headerlen + datalen
            datalen += len(self[OWNER_SID].get_data(force_recompute=force_recompute))
        else:
            self[OFFSET_OWNER] = 0

        if self[GROUP_SID] != b'':
            self[OFFSET_GROUP] = headerlen + datalen
            datalen += len(self[GROUP_SID].get_data(force_recompute=force_recompute))
        else:
            self[OFFSET_GROUP] = 0
        return Structure.get_data(self, force_recompute=force_recompute)


class ACE(Structure):
    """
    ACE as described in 2.4.4
    Class renamed to match python naming conventions.
    https://msdn.microsoft.com/en-us/library/cc230295.aspx
    """
    # Flag constants
    CONTAINER_INHERIT_ACE = 0x02
    FAILED_ACCESS_ACE_FLAG = 0x80
    INHERIT_ONLY_ACE = 0x08
    INHERITED_ACE = 0x10
    NO_PROPAGATE_INHERIT_ACE = 0x04
    OBJECT_INHERIT_ACE = 0x01
    SUCCESSFUL_ACCESS_ACE_FLAG = 0x40

    structure = (
        #
        # ACE_HEADER as described in 2.4.4.1
        # https://msdn.microsoft.com/en-us/library/cc230296.aspx
        #
        (ACE_TYPE, 'B'),
        (ACE_FLAGS, 'B'),
        (ACE_SIZE, '<H'),
        # Virtual field to calculate data length from AceSize
        (ACE_LEN, '_-{}'.format(ACE_BODY), 'self["{}"]-4'.format(ACE_SIZE)),
        # ACE body, is parsed depending on the type
        (ACE_BODY, ':')
    )
    REPR_NAME = 'ACE'

    def parse_structure_from_bytes(self, data: bytes):
        # This will parse the header
        Structure.parse_structure_from_bytes(self, data)
        # Now we parse the ACE body according to its type
        self[ACE_TYPE_NAME] = ACE_TYPE_MAP[self[ACE_TYPE]].__name__
        self[ACE_BODY] = ACE_TYPE_MAP[self[ACE_TYPE]](data=self[ACE_BODY], parent_structure=self)

    def get_data(self, force_recompute: bool = False):
        if ACE_SIZE not in self.fields:
            # include our 4 byte header size in the ACE size, in addition to the size of our body
            self[ACE_SIZE] = len(self[ACE_BODY].get_data(force_recompute=force_recompute)) + 4
        # Make sure the alignment is correct
        if self[ACE_SIZE] % 4 != 0:
            self[ACE_SIZE] += 4 - (self[ACE_SIZE] % 4)
        data = Structure.get_data(self, force_recompute=force_recompute)
        # For some reason ACEs are sometimes longer than they need to be
        # we fill this space up with null bytes to make sure the object
        # we create is identical to the original object
        if len(data) < self[ACE_SIZE]:
            data += '\x00' * (self[ACE_SIZE] - len(data))
        return data

    def has_flag(self, flag):
        return self[ACE_FLAGS] & flag == flag


class AccessMask(Structure):
    """
    ACCESS_MASK as described in 2.4.3
    Class renamed to match python naming conventions.
    https://msdn.microsoft.com/en-us/library/cc230294.aspx
    """
    # Flag constants
    GENERIC_READ = 0x80000000
    GENERIC_WRITE = 0x04000000
    GENERIC_EXECUTE = 0x20000000
    GENERIC_ALL = 0x10000000
    MAXIMUM_ALLOWED = 0x02000000
    ACCESS_SYSTEM_SECURITY = 0x01000000
    SYNCHRONIZE = 0x00100000
    WRITE_OWNER = 0x00080000
    WRITE_DACL = 0x00040000
    READ_CONTROL = 0x00020000
    DELETE = 0x00010000  # this is what can give us SELF DELETE

    structure = (
        (MASK, '<L'),
    )
    REPR_NAME = 'AccessMask'

    def has_privilege(self, priv):
        return self[MASK] & priv == priv

    def set_privilege(self, priv):
        self[MASK] |= priv

    def remove_privilege(self, priv):
        self[MASK] ^= priv


class AccessAllowedAce(Structure):
    """
    ACCESS_ALLOWED_ACE as described in 2.4.4.2
    Class renamed to match python naming conventions.
    https://msdn.microsoft.com/en-us/library/cc230286.aspx
    """
    ACE_TYPE = 0x00
    structure = (
        (MASK, ':', AccessMask),
        (SID, ':', ObjectSid)
    )
    REPR_NAME = 'AccessAllowedAce'


class AccessAllowedObjectAce(Structure):
    """
    ACCESS_ALLOWED_OBJECT_ACE as described in 2.4.4.3
    Class renamed to match python naming conventions.
    https://msdn.microsoft.com/en-us/library/cc230289.aspx
    """
    ACE_TYPE = 0x05

    # Flag contstants
    ACE_OBJECT_TYPE_PRESENT = 0x01
    ACE_INHERITED_OBJECT_TYPE_PRESENT = 0x02

    # ACE type specific mask constants
    # These also appear to be valid for ACCESS_ALLOWED_ACE types, though documentation
    # for that doesn't exist.
    ADS_RIGHT_DS_CONTROL_ACCESS = 0x00000100
    ADS_RIGHT_DS_CREATE_CHILD = 0x00000001
    ADS_RIGHT_DS_DELETE_CHILD = 0x00000002
    ADS_RIGHT_DS_READ_PROP = 0x00000010
    ADS_RIGHT_DS_WRITE_PROP = 0x00000020
    ADS_RIGHT_DS_SELF = 0x00000008

    structure = (
        (MASK, ':', AccessMask),
        (FLAGS, '<L'),
        # Optional field
        (OBJECT_TYPE_LEN, '_-{}'.format(OBJECT_TYPE),
         'self.check_object_type(self["{}"])'.format(FLAGS)),
        (OBJECT_TYPE, ':=""'),
        # Optional field
        (INHERITED_OBJECT_TYPE_LEN, '_-{}'.format(INHERITED_OBJECT_TYPE),
         'self.check_inherited_object_type(self["{}"])'.format(FLAGS)),
        (INHERITED_OBJECT_TYPE, ':=""'),
        (SID, ':', ObjectSid)
    )
    REPR_NAME = 'AccessAllowedObjectAce'

    @staticmethod
    def check_inherited_object_type(flags):
        if flags & AccessAllowedObjectAce.ACE_INHERITED_OBJECT_TYPE_PRESENT:
            return 16
        return 0

    @staticmethod
    def check_object_type(flags):
        if flags & AccessAllowedObjectAce.ACE_OBJECT_TYPE_PRESENT:
            return 16
        return 0

    def get_data(self, force_recompute=False):
        # Set the correct flags
        if self[OBJECT_TYPE] != b'':
            self[FLAGS] |= self.ACE_OBJECT_TYPE_PRESENT
        if self[INHERITED_OBJECT_TYPE] != b'':
            self[FLAGS] |= self.ACE_INHERITED_OBJECT_TYPE_PRESENT
        return Structure.get_data(self, force_recompute=force_recompute)

    def has_flag(self, flag):
        return self[FLAGS] & flag == flag


class AccessDeniedAce(AccessAllowedAce):
    """
    ACCESS_DENIED_ACE as described in 2.4.4.4
    Class renamed to match python naming conventions.
    https://msdn.microsoft.com/en-us/library/cc230291.aspx
    Structure is identical to ACCESS_ALLOWED_ACE
    """
    ACE_TYPE = 0x01
    REPR_NAME = 'AccessDeniedAce'


class AccessDeniedObjectAce(AccessAllowedObjectAce):
    """
    ACCESS_DENIED_OBJECT_ACE as described in 2.4.4.5
    Class renamed to match python naming conventions.
    https://msdn.microsoft.com/en-us/library/gg750297.aspx
    Structure is identical to ACCESS_ALLOWED_OBJECT_ACE
    """
    ACE_TYPE = 0x06
    REPR_NAME = 'AccessDeniedObjectAce'


class AccessAllowedCallbackAce(Structure):
    """
    ACCESS_ALLOWED_CALLBACK_ACE as described in 2.4.4.6
    Class renamed to match python naming conventions.
    https://msdn.microsoft.com/en-us/library/cc230287.aspx
    """
    ACE_TYPE = 0x09
    structure = (
        (MASK, ':', AccessMask),
        (SID, ':', ObjectSid),
        (APPLICATION_DATA, ':')
    )
    REPR_NAME = 'AccessAllowedCallbackAce'


class AccessDeniedCallbackAce(AccessAllowedCallbackAce):
    """
    ACCESS_DENIED_CALLBACK_ACE as described in 2.4.4.7
    Class renamed to match python naming conventions.
    https://msdn.microsoft.com/en-us/library/cc230292.aspx
    Structure is identical to ACCESS_ALLOWED_CALLBACK_ACE
    """
    ACE_TYPE = 0x0A
    REPR_NAME = 'AccessDeniedCallbackAce'


class AccessAllowedCallbackObjectAce(AccessAllowedObjectAce):
    """
    ACCESS_ALLOWED_CALLBACK_OBJECT_ACE as described in 2.4.4.8
    Class renamed to match python naming conventions.
    https://msdn.microsoft.com/en-us/library/cc230288.aspx
    """
    ACE_TYPE = 0x0B
    structure = (
        (MASK, ':', AccessMask),
        (FLAGS, '<L'),
        # Optional field
        (OBJECT_TYPE_LEN, '_-{}'.format(OBJECT_TYPE),
         'self.check_object_type(self["{}"])'.format(FLAGS)),
        (OBJECT_TYPE, ':=""'),
        # Optional field
        (INHERITED_OBJECT_TYPE_LEN, '_-{}'.format(INHERITED_OBJECT_TYPE),
         'self.check_inherited_object_type(self["{}"])'.format(FLAGS)),
        (INHERITED_OBJECT_TYPE, ':=""'),
        (SID, ':', ObjectSid),
        (APPLICATION_DATA, ':')
    )
    REPR_NAME = 'AccessAllowedCallbackObjectAce'


class AccessDeniedCallbackObjectAce(AccessAllowedCallbackObjectAce):
    """
    ACCESS_DENIED_CALLBACK_OBJECT_ACE as described in 2.4.4.7
    Class renamed to match python naming conventions.
    https://msdn.microsoft.com/en-us/library/cc230292.aspx
    Structure is identical to ACCESS_ALLOWED_OBJECT_OBJECT_ACE
    """
    ACE_TYPE = 0x0C
    REPR_NAME = 'AccessDeniedCallbackObjectAce'


class SystemAuditAce(AccessAllowedAce):
    """
    SYSTEM_AUDIT_ACE as described in 2.4.4.10
    Class renamed to match python naming conventions.
    https://msdn.microsoft.com/en-us/library/cc230376.aspx
    Structure is identical to ACCESS_ALLOWED_ACE
    """
    ACE_TYPE = 0x02
    REPR_NAME = 'SystemAuditAce'


class SystemAuditObjectAce(AccessAllowedCallbackObjectAce):
    """
    SYSTEM_AUDIT_OBJECT_ACE as described in 2.4.4.11
    Class renamed to match python naming conventions.
    https://msdn.microsoft.com/en-us/library/gg750298.aspx
    Structure is identical to ACCESS_ALLOWED_CALLBACK_OBJECT_ACE
    """
    ACE_TYPE = 0x07
    REPR_NAME = 'SystemAuditObjectAce'


class SystemAuditCallbackAce(AccessAllowedCallbackAce):
    """
    SYSTEM_AUDIT_CALLBACK_ACE as described in 2.4.4.12
    Class renamed to match python naming conventions.
    https://msdn.microsoft.com/en-us/library/cc230377.aspx
    Structure is identical to ACCESS_ALLOWED_CALLBACK_ACE
    """
    ACE_TYPE = 0x0D
    REPR_NAME = 'SystemAuditCallbackAce'


class SystemMandatoryLabelAce(Structure):
    """
    SYSTEM_MANDATORY_LABEL_ACE as described in 2.4.4.13
    Class renamed to match python naming conventions.
    https://msdn.microsoft.com/en-us/library/cc230379.aspx
    Structure is identical to ACCESS_ALLOWED_ACE, but with custom masks and meanings.
    """
    ACE_TYPE = 0x11
    structure = (
        (MASK, ':', AccessMask),
        (SID, ':', ObjectSid)
    )
    REPR_NAME = 'SystemMandatoryLabelAce'


class SystemAuditCallbackObjectAce(AccessAllowedCallbackObjectAce):
    """
    SYSTEM_AUDIT_CALLBACK_OBJECT_ACE as described in 2.4.4.14
    Class renamed to match python naming conventions.
    https://msdn.microsoft.com/en-us/library/cc230378.aspx
    Structure is identical to ACCESS_ALLOWED_CALLBACK_OBJECT_ACE
    """
    ACE_TYPE = 0x0F
    REPR_NAME = 'SystemAuditCallbackObjectAce'


class SystemResourceAttributeAce(AccessAllowedCallbackAce):
    """
    SYSTEM_RESOURCE_ATTRIBUTE_ACE as described in 2.4.4.15
    Class renamed to match python naming conventions.
    https://msdn.microsoft.com/en-us/library/hh877837.aspx
    Structure is identical to ACCESS_ALLOWED_CALLBACK_ACE
    The application data however is encoded in CLAIM_SECURITY_ATTRIBUTE_RELATIVE_V1
    format as described in section 2.4.10.1
    """
    ACE_TYPE = 0x12
    REPR_NAME = 'SystemResourceAttributeAce'


class SystemScopedPolicyIdAce(AccessAllowedAce):
    """
    SYSTEM_SCOPED_POLICY_ID_ACE as described in 2.4.4.16
    Class renamed to match python naming conventions.
    https://msdn.microsoft.com/en-us/library/hh877846.aspx
    Structure is identical to ACCESS_ALLOWED_ACE
    The ACCESS_MASK must always be 0
    """
    ACE_TYPE = 0x13
    REPR_NAME = 'SystemScopedPolicyIdAce'


# All the ACE types in a list
ACE_TYPES = [
    AccessAllowedAce,
    AccessAllowedObjectAce,
    AccessDeniedAce,
    AccessDeniedObjectAce,
    AccessAllowedCallbackAce,
    AccessDeniedCallbackAce,
    AccessAllowedCallbackObjectAce,
    AccessDeniedCallbackObjectAce,
    SystemAuditAce,
    SystemAuditObjectAce,
    SystemAuditCallbackAce,
    SystemMandatoryLabelAce,
    SystemAuditCallbackObjectAce,
    SystemResourceAttributeAce,
    SystemScopedPolicyIdAce
]

# A dict of all the ACE types indexed by their type number
ACE_TYPE_MAP = {ace.ACE_TYPE: ace for ace in ACE_TYPES}


class ACL(Structure):
    """
    ACL as described in 2.4.5
    https://msdn.microsoft.com/en-us/library/cc230297.aspx
    """
    structure = (
        (ACL_REVISION, 'B'),
        (SBZ1, 'B'),
        (ACL_SIZE, '<H'),
        (ACE_COUNT, '<H'),
        (SBZ2, '<H'),
        # Virtual field to calculate data length from AclSize
        (DATA_LEN, '_-{}'.format(DATA), 'self["{}"]-8'.format(ACL_SIZE)),
        (DATA, ':'),
    )
    REPR_NAME = 'ACL'
    aces = []

    def parse_structure_from_bytes(self, data: bytes):
        self.aces = []
        Structure.parse_structure_from_bytes(self, data)
        for i in range(self[ACE_COUNT]):
            # If we don't have any data left, return
            if len(self[DATA]) == 0:
                raise SecurityDescriptorDecodeException("ACL header indicated there are more ACLs to unpack, but "
                                                        "there is no more data encoded.")
            ace = ACE(data=self[DATA], parent_structure=self)
            self.aces.append(ace)
            self[DATA] = self[DATA][ace[ACE_SIZE]:]
        self[DATA] = self.aces

    def get_data(self, force_recompute: bool = False):
        self[ACE_COUNT] = len(self.aces)
        # We modify the data field to be able to use the
        # parent class parsing
        self[DATA] = b''.join([ace.get_data(force_recompute=force_recompute) for ace in self.aces])
        self[ACL_SIZE] = len(self[DATA]) + 8  # Header size (8 bytes) is included
        data = Structure.get_data(self, force_recompute=force_recompute)
        # Put the ACEs back in data
        self[DATA] = self.aces
        return data

    def append_aces(self, new_aces: List[ACE]):
        self.aces.extend(new_aces)
        self.reset_data()

    def append_ace(self, new_ace: ACE):
        self.aces.append(new_ace)
        self.reset_data()

    def prepend_aces(self, new_aces: List[ACE]):
        self.aces = new_aces + self.aces
        self.reset_data()

    def prepend_ace(self, new_ace: ACE):
        self.aces = [new_ace] + self.aces
        self.reset_data()
