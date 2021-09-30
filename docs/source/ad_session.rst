``ADSession`` Objects
#######################


Help for the class ``ADSession`` in module ``ms_active_directory.core.ad_session`` follows:

Manually creating an ``ADSession``
----------------------------------

While it's recommended that you create ``ADSession`` objects from ``ADDomain`` objects,
you can manually create them given a domain and an LDAP connection to it.

The function to do so is as follows::

    class ADSession(builtins.object)
        ADSession(ldap_connection: ldap3.core.connection.Connection, domain: 'ADDomain', search_paging_size: int = 100, trusted_domain_cache_lifetime_seconds: int = 86400)

        Methods defined here:

        __init__(self, ldap_connection: ldap3.core.connection.Connection, domain: 'ADDomain', search_paging_size: int = 100, trusted_domain_cache_lifetime_seconds: int = 86400)
            Create a session object for a connection to an AD domain.
            Given an LDAP connection, a domain, and optional parameters relating to searches and multi-domain
            functionality, create an ADSession object.

            :param ldap_connection: An ldap3 Connection object representing the connection to LDAP servers within
                                    the domain.
            :param domain: An ADDomain object representing the domain that we're communicating with.
            :param search_paging_size: Optional. The page size for paginated searches. If a search is expected to
                                       be able to have more than this many results, a paginated search will be
                                       performed. This is used as the page size in such searches. Changing this
                                       affects the balance between the number of queries made and the size of
                                       each query response in a large scale environment, and so it can be used
                                       to optimize behavior based on network topology and traffic.
                                       If not specified, defaults to 100.
            :param trusted_domain_cache_lifetime_seconds: Optional. How long to maintain our trusted domain cache in
                                                          seconds. The cache of trusted domain information exists because
                                                          trust relationships change infrequently, but will be used a lot
                                                          in searches and such when automatic traversal of trusts is
                                                          supported. Can be set to 0 to disable the cache.
                                                          If not specified, defaults to 24 hours.

        __repr__(self)
            Return repr(self).

        __str__(self)
            Return str(self).

        add_computers_to_groups(self, computers_to_add: List[Union[str, ms_active_directory.core.ad_objects.ADComputer]], groups_to_add_them_to: List[Union[str, ms_active_directory.core.ad_objects.ADGroup]], stop_and_rollback_on_error: bool = True, controls: List[ldap3.protocol.rfc4511.Control] = None, skip_validation: bool = False) -> List[Union[str, ms_active_directory.core.ad_objects.ADGroup]]
            Add one or more computers to one or more groups as members. This function attempts to be idempotent
            and will not re-add computers that are already members.

            :param computers_to_add: A list of computers to add to other groups. These may either be ADComputer objects or
                                     string name identifiers for computers.
            :param groups_to_add_them_to: A list of groups to add members to. These may either be ADGroup objects or string
                                          name identifiers for groups.
            :param stop_and_rollback_on_error: If true, failure to add any of the computers to any of the groups will
                                               cause us to try and remove any computers that have been added from any of the
                                               groups that we successfully added members to.
            :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                             whether or not certain properties/attributes are critical, which influences whether a search
                             may succeed or fail based on their availability.
            :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                    Defaults to False. This can be used to make this function more performant when
                                    the caller knows all the distinguished names being specified are valid, as it
                                    performs far fewer queries.
            :returns: A list of groups that successfully had members added. This will always be all the groups unless
                      stop_and_rollback_on_error is False.
            :raises: MembershipModificationException if we fail to add groups to any other groups and rollback succeeds.
            :raises: MembershipModificationRollbackException if we fail to add any groups to other groups, and then also
                     fail when removing the groups that had been added successfully, leaving us in a partially completed
                     state. This may occur if the session has permission to add members but not to remove members.

        add_groups_to_groups(self, groups_to_add: List[Union[str, ms_active_directory.core.ad_objects.ADGroup]], groups_to_add_them_to: List[Union[str, ms_active_directory.core.ad_objects.ADGroup]], stop_and_rollback_on_error: bool = True, controls: List[ldap3.protocol.rfc4511.Control] = None, skip_validation: bool = False) -> List[Union[str, ms_active_directory.core.ad_objects.ADGroup]]
            Add one or more groups to one or more other groups as members. This function attempts to be idempotent
            and will not re-add groups that are already members.

            :param groups_to_add: A list of groups to add to other groups. These may either be ADGroup objects or string
                                  name identifiers for groups.
            :param groups_to_add_them_to: A list of groups to add members to. These may either be ADGroup objects or string
                                          name identifiers for groups.
            :param stop_and_rollback_on_error: If true, failure to add any of the groups to any of the other groups will
                                               cause us to try and remove any groups that have been added from any of the
                                               groups that we successfully added members to.
            :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                             whether or not certain properties/attributes are critical, which influences whether a search
                             may succeed or fail based on their availability.
            :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                    Defaults to False. This can be used to make this function more performant when
                                    the caller knows all the distinguished names being specified are valid, as it
                                    performs far fewer queries.
            :returns: A list of groups that successfully had members added. This will always be all the groups unless
                      stop_and_rollback_on_error is False.
            :raises: MembershipModificationException if any groups being added also exist in the groups to add them to, or
                     if we fail to add groups to any other groups and rollback succeeds.
            :raises: MembershipModificationRollbackException if we fail to add any groups to other groups, and then also
                     fail when removing the groups that had been added successfully, leaving us in a partially completed
                     state. This may occur if the session has permission to add members but not to remove members.

        add_permission_to_computer_security_descriptor(self, computer: Union[str, ms_active_directory.core.ad_objects.ADComputer], sids_to_grant_permissions_to: List[Union[str, ms_active_directory.environment.security.security_descriptor_utils.ObjectSid, ms_active_directory.environment.security.security_config_constants.WellKnownSID]], access_masks_to_add: List[ms_active_directory.environment.security.security_descriptor_utils.AccessMask] = None, rights_guids_to_add: List[Union[ms_active_directory.environment.security.ad_security_guids.ADRightsGuid, str]] = None, read_property_guids_to_add: List[str] = None, write_property_guids_to_add: List[str] = None, raise_exception_on_failure: bool = True, skip_validation: bool = False) -> bool
            Add specified permissions to the security descriptor on a computer for specified SIDs.
            This can be used to grant 1 or more other users/groups/computers/etc. the right to take broad actions or narrow
            privileged actions on the computer, via adding access masks or rights guids respectively. It can also give
            1 or more users/groups/computers/etc. the ability to read or write specific properties on the user by
            specifying read or write property guids to add.

            This can, as an example, take a computer and give a user the right to delete it. Or take a computer
            and give a list of computers the right to read and write the user's owner SID. Or take a computer and let
            another user reset their password without needing the current one. Etc. Etc.

            :param computer: An ADComputer or String distinguished name, referring to the computer that will have the
                             permissions on it modified.
            :param sids_to_grant_permissions_to: SIDs referring to the other entities that will be given new permissions
                                                 on the user. These may be ObjectSID objects, SID strings, or
                                                 WellKnownSIDs.
            :param access_masks_to_add: A list of AccessMask objects to grant to the SIDs. These represent broad categories
                                        of actions, such as GENERIC_READ and GENERIC_WRITE.
            :param rights_guids_to_add: A list of rights guids to grant to the SIDs. These may be specified as strings or
                                        as ADRightsGuid enums, and represent narrower permissions to grant to the SIDs for
                                        targeted actions such as Unexpire_Password or Apply_Group_Policy. Some of these
                                        do not make logical sense to use in all contexts, as some rights guids only have
                                        meaning in a self-relative context, or only have meaning on some object types.
                                        It is left up to the caller to decide what is meaningful.
            :param read_property_guids_to_add: A list of property guids that represent properties of the computer that the
                                               SIDs will be granted the right to read. These must be strings.
            :param write_property_guids_to_add: A list of property guids that represent properties of the computer that the
                                                SIDs will be granted the right to write. These must be strings.
            :param raise_exception_on_failure: A boolean indicating if an exception should be raised if we fail to update
                                               the security descriptor, instead of returning False. defaults to True
            :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                    Defaults to False. This can be used to make this function more performant when
                                    the caller knows all the distinguished names being specified are valid, as it
                                    performs far fewer queries.
            :returns: A boolean indicating if we succeeded in updating the security descriptor.
            :raises: InvalidLdapParameterException if any inputs are the wrong type.
            :raises: ObjectNotFoundException if the a string distinguished name is specified and cannot be found.
            :raises: PermissionDeniedException if we fail to modify the Security Descriptor and raise_exception_on_failure
                     is true

        add_permission_to_group_security_descriptor(self, group, sids_to_grant_permissions_to: List[Union[str, ms_active_directory.environment.security.security_descriptor_utils.ObjectSid, ms_active_directory.environment.security.security_config_constants.WellKnownSID]], access_masks_to_add: List[ms_active_directory.environment.security.security_descriptor_utils.AccessMask] = None, rights_guids_to_add: List[Union[ms_active_directory.environment.security.ad_security_guids.ADRightsGuid, str]] = None, read_property_guids_to_add: List[str] = None, write_property_guids_to_add: List[str] = None, raise_exception_on_failure: bool = True, skip_validation: bool = False) -> bool
            Add specified permissions to the security descriptor on a group for specified SIDs.
            This can be used to grant 1 or more other users/groups/computers/etc. the right to take broad actions or narrow
            privileged actions on the group, via adding access masks or rights guids respectively. It can also give
            1 or more users/groups/computers/etc. the ability to read or write specific properties on the group by
            specifying read or write property guids to add.

            This can, as an example, take a group and give another group the right to delete it. Or take a group
            and give a list of computers the right to read the group's SID. Or take a group and let another user
            add members to it. Etc. Etc.

            :param group: An ADGroup or String distinguished name, referring to the group that will have the permissions on
                          it modified.
            :param sids_to_grant_permissions_to: SIDs referring to the other entities that will be given new permissions
                                                 on the group. These may be ObjectSID objects, SID strings, or
                                                 WellKnownSIDs.
            :param access_masks_to_add: A list of AccessMask objects to grant to the SIDs. These represent broad categories
                                        of actions, such as GENERIC_READ and GENERIC_WRITE.
            :param rights_guids_to_add: A list of rights guids to grant to the SIDs. These may be specified as strings or
                                        as ADRightsGuid enums, and represent narrower permissions to grant to the SIDs for
                                        targeted actions such as Unexpire_Password or Apply_Group_Policy. Some of these
                                        do not make logical sense to use in all contexts, as some rights guids only have
                                        meaning in a self-relative context, or only have meaning on some object types.
                                        It is left up to the caller to decide what is meaningful.
            :param read_property_guids_to_add: A list of property guids that represent properties of the group that the
                                               SIDs will be granted the right to read. These must be strings.
            :param write_property_guids_to_add: A list of property guids that represent properties of the group that the
                                                SIDs will be granted the right to write. These must be strings.
            :param raise_exception_on_failure: A boolean indicating if an exception should be raised if we fail to update
                                               the security descriptor, instead of returning False. defaults to True
            :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                    Defaults to False. This can be used to make this function more performant when
                                    the caller knows all the distinguished names being specified are valid, as it
                                    performs far fewer queries.
            :returns: A boolean indicating if we succeeded in updating the security descriptor.
            :raises: InvalidLdapParameterException if any inputs are the wrong type.
            :raises: ObjectNotFoundException if the a string distinguished name is specified and cannot be found.
            :raises: PermissionDeniedException if we fail to modify the Security Descriptor and raise_exception_on_failure
                     is true

        add_permission_to_object_security_descriptor(self, ad_object_to_modify: Union[str, ms_active_directory.core.ad_objects.ADObject], sids_to_grant_permissions_to: List[Union[str, ms_active_directory.environment.security.security_descriptor_utils.ObjectSid, ms_active_directory.environment.security.security_config_constants.WellKnownSID]], access_masks_to_add: List[ms_active_directory.environment.security.security_descriptor_utils.AccessMask] = None, rights_guids_to_add: List[Union[ms_active_directory.environment.security.ad_security_guids.ADRightsGuid, str]] = None, read_property_guids_to_add: List[str] = None, write_property_guids_to_add: List[str] = None, raise_exception_on_failure: bool = True, skip_validation: bool = False) -> bool
            Add specified permissions to the security descriptor on an object for specified SIDs.
            This can be used to grant 1 or more other users/groups/computers/etc. the right to take broad actions or narrow
            privileged actions on the object, via adding access masks or rights guids respectively. It can also give
            1 or more users/groups/computers/etc. the ability to read or write specific properties on the object by
            specifying read or write property guids to add.

            This can, as an example, take a container object and give a user the right to delete it. Or take a group object
            and give a list of computers the right to read and write the group's members. Or take a computer and let a user
            reset its password without needing the current one. Etc. Etc.

            :param ad_object_to_modify: An ADObject or String distinguished name, referring to the object that will have
                                        the permissions on it modified.
            :param sids_to_grant_permissions_to: SIDs referring to the other entities that will be given new permissions
                                                 on the object. These may be ObjectSID objects, SID strings, or
                                                 WellKnownSIDs.
            :param access_masks_to_add: A list of AccessMask objects to grant to the SIDs. These represent broad categories
                                        of actions, such as GENERIC_READ and GENERIC_WRITE.
            :param rights_guids_to_add: A list of rights guids to grant to the SIDs. These may be specified as strings or
                                        as ADRightsGuid enums, and represent narrower permissions to grant to the SIDs for
                                        targeted actions such as Unexpire_Password or Apply_Group_Policy. Some of these
                                        do not make logical sense to use in all contexts, as some rights guids only have
                                        meaning in a self-relative context, or only have meaning on some object types.
                                        It is left up to the caller to decide what is meaningful.
            :param read_property_guids_to_add: A list of property guids that represent properties of the object that the
                                               SIDs will be granted the right to read. These must be strings.
            :param write_property_guids_to_add: A list of property guids that represent properties of the object that the
                                                SIDs will be granted the right to write. These must be strings.
            :param raise_exception_on_failure: A boolean indicating if an exception should be raised if we fail to update
                                               the security descriptor, instead of returning False. defaults to True
            :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                    Defaults to False. This can be used to make this function more performant when
                                    the caller knows all the distinguished names being specified are valid, as it
                                    performs far fewer queries.
            :returns: A boolean indicating if we succeeded in updating the security descriptor.
            :raises: InvalidLdapParameterException if any inputs are the wrong type.
            :raises: ObjectNotFoundException if the a string distinguished name is specified and cannot be found.
            :raises: PermissionDeniedException if we fail to modify the Security Descriptor and raise_exception_on_failure
                     is true

        add_permission_to_user_security_descriptor(self, user: Union[str, ms_active_directory.core.ad_objects.ADUser], sids_to_grant_permissions_to: List[Union[str, ms_active_directory.environment.security.security_descriptor_utils.ObjectSid, ms_active_directory.environment.security.security_config_constants.WellKnownSID]], access_masks_to_add: List[ms_active_directory.environment.security.security_descriptor_utils.AccessMask] = None, rights_guids_to_add: List[Union[ms_active_directory.environment.security.ad_security_guids.ADRightsGuid, str]] = None, read_property_guids_to_add: List[str] = None, write_property_guids_to_add: List[str] = None, raise_exception_on_failure: bool = True, skip_validation: bool = False) -> bool
            Add specified permissions to the security descriptor on a user for specified SIDs.
            This can be used to grant 1 or more other users/groups/computers/etc. the right to take broad actions or narrow
            privileged actions on the user, via adding access masks or rights guids respectively. It can also give
            1 or more users/groups/computers/etc. the ability to read or write specific properties on the user by
            specifying read or write property guids to add.

            This can, as an example, take a user and give another user the right to delete it. Or take a user
            and give a list of computers the right to read and write the user's owner SID. Or take a user and let another
            user reset their password without needing the current one. Etc. Etc.

            :param user: An ADUser or String distinguished name, referring to the user that will have the permissions on it
                         modified.
            :param sids_to_grant_permissions_to: SIDs referring to the other entities that will be given new permissions
                                                 on the user. These may be ObjectSID objects, SID strings, or
                                                 WellKnownSIDs.
            :param access_masks_to_add: A list of AccessMask objects to grant to the SIDs. These represent broad categories
                                        of actions, such as GENERIC_READ and GENERIC_WRITE.
            :param rights_guids_to_add: A list of rights guids to grant to the SIDs. These may be specified as strings or
                                        as ADRightsGuid enums, and represent narrower permissions to grant to the SIDs for
                                        targeted actions such as Unexpire_Password or Apply_Group_Policy. Some of these
                                        do not make logical sense to use in all contexts, as some rights guids only have
                                        meaning in a self-relative context, or only have meaning on some object types.
                                        It is left up to the caller to decide what is meaningful.
            :param read_property_guids_to_add: A list of property guids that represent properties of the user that the
                                               SIDs will be granted the right to read. These must be strings.
            :param write_property_guids_to_add: A list of property guids that represent properties of the user that the
                                                SIDs will be granted the right to write. These must be strings.
            :param raise_exception_on_failure: A boolean indicating if an exception should be raised if we fail to update
                                               the security descriptor, instead of returning False. defaults to True
            :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                    Defaults to False. This can be used to make this function more performant when
                                    the caller knows all the distinguished names being specified are valid, as it
                                    performs far fewer queries.
            :returns: A boolean indicating if we succeeded in updating the security descriptor.
            :raises: InvalidLdapParameterException if any inputs are the wrong type.
            :raises: ObjectNotFoundException if the a string distinguished name is specified and cannot be found.
            :raises: PermissionDeniedException if we fail to modify the Security Descriptor and raise_exception_on_failure
                     is true

        add_users_to_groups(self, users_to_add: List[Union[str, ms_active_directory.core.ad_objects.ADUser]], groups_to_add_them_to: List[Union[str, ms_active_directory.core.ad_objects.ADGroup]], stop_and_rollback_on_error: bool = True, controls: List[ldap3.protocol.rfc4511.Control] = None, skip_validation: bool = False) -> List[Union[str, ms_active_directory.core.ad_objects.ADGroup]]
            Add one or more users to one or more groups as members. This function attempts to be idempotent
            and will not re-add users that are already members.

            :param users_to_add: A list of users to add to other groups. These may either be ADUser objects or string
                                 name identifiers for users.
            :param groups_to_add_them_to: A list of groups to add members to. These may either be ADGroup objects or string
                                          name identifiers for groups.
            :param stop_and_rollback_on_error: If true, failure to add any of the users to any of the groups will
                                               cause us to try and remove any users that have been added from any of the
                                               groups that we successfully added members to.
            :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                             whether or not certain properties/attributes are critical, which influences whether a search
                             may succeed or fail based on their availability.
            :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                    Defaults to False. This can be used to make this function more performant when
                                    the caller knows all the distinguished names being specified are valid, as it
                                    performs far fewer queries.
            :returns: A list of groups that successfully had members added. This will always be all the groups unless
                      stop_and_rollback_on_error is False.
            :raises: MembershipModificationException if we fail to add groups to any other groups and rollback succeeds.
            :raises: MembershipModificationRollbackException if we fail to add any groups to other groups, and then also
                     fail when removing the groups that had been added successfully, leaving us in a partially completed
                     state. This may occur if the session has permission to add members but not to remove members.

        atomic_append_to_attribute_for_computer(self, computer: Union[str, ms_active_directory.core.ad_objects.ADComputer], attribute: str, value, controls: List[ldap3.protocol.rfc4511.Control] = None, raise_exception_on_failure: bool = True, skip_validation: bool = False) -> bool
            Atomically append a value to an attribute for a computer in the domain.

            :param computer: Either an ADComputer object or string name referencing the computer to be modified.
            :param attribute: A string specifying the name of the LDAP attribute to be appended to.
            :param value: The value to append to the attribute. Value may either be a primitive, such as a string, bytes,
                          or a number, if a single value will be appended. Value may also be an iterable such as a set or
                          a list if a multi-valued attribute will be appended to, in order to append multiple new values
                          to it at once.
            :param controls: LDAP controls to use during the modification operation.
            :param raise_exception_on_failure: If true, an exception will be raised with additional details if the modify
                                               fails.
            :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                    Defaults to False. This can be used to make this function more performant when
                                    the caller knows all the distinguished names being specified are valid, as it
                                    performs far fewer queries.
            :returns: True if the operation succeeds, False otherwise.
            :raises: InvalidLdapParameterException if any attributes or values are malformed.
            :raises: ObjectNotFoundException if a distinguished name is specified and cannot be found
            :raises: AttributeModificationException if raise_exception_on_failure is True and we fail
            :raises: Other LDAP exceptions from the ldap3 library if the connection is configured to raise exceptions and
                     issues are seen such as determining that a value is malformed based on the server schema.

        atomic_append_to_attribute_for_group(self, group: Union[str, ms_active_directory.core.ad_objects.ADGroup], attribute: str, value, controls: List[ldap3.protocol.rfc4511.Control] = None, raise_exception_on_failure: bool = True, skip_validation: bool = False) -> bool
            Atomically append a value to an attribute for a group in the domain.

            :param group: Either an ADGroup object or string name referencing the group to be modified.
            :param attribute: A string specifying the name of the LDAP attribute to be appended to.
            :param value: The value to append to the attribute. Value may either be a primitive, such as a string, bytes,
                          or a number, if a single value will be appended. Value may also be an iterable such as a set or
                          a list if a multi-valued attribute will be appended to, in order to append multiple new values
                          to it at once.
            :param controls: LDAP controls to use during the modification operation.
            :param raise_exception_on_failure: If true, an exception will be raised with additional details if the modify
                                               fails.
            :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                    Defaults to False. This can be used to make this function more performant when
                                    the caller knows all the distinguished names being specified are valid, as it
                                    performs far fewer queries.
            :returns: True if the operation succeeds, False otherwise.
            :raises: InvalidLdapParameterException if any attributes or values are malformed.
            :raises: ObjectNotFoundException if a distinguished name is specified and cannot be found
            :raises: AttributeModificationException if raise_exception_on_failure is True and we fail
            :raises: Other LDAP exceptions from the ldap3 library if the connection is configured to raise exceptions and
                     issues are seen such as determining that a value is malformed based on the server schema.

        atomic_append_to_attribute_for_object(self, ad_object: Union[str, ms_active_directory.core.ad_objects.ADObject], attribute: str, value, controls: List[ldap3.protocol.rfc4511.Control] = None, raise_exception_on_failure: bool = True, skip_validation: bool = False) -> bool
            Atomically append a value to an attribute for an object in the domain.

            :param ad_object: Either an ADObject object or string distinguished name referencing the object to be modified.
            :param attribute: A string specifying the name of the LDAP attribute to be appended to.
            :param value: The value to append to the attribute. Value may either be a primitive, such as a string, bytes,
                          or a number, if a single value will be appended. Value may also be an iterable such as a set or
                          a list if a multi-valued attribute will be appended to, in order to append multiple new values
                          to it at once.
            :param controls: LDAP controls to use during the modification operation.
            :param raise_exception_on_failure: If true, an exception will be raised with additional details if the modify
                                               fails.
            :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                    Defaults to False. This can be used to make this function more performant when
                                    the caller knows all the distinguished names being specified are valid, as it
                                    performs far fewer queries.
            :returns: True if the operation succeeds, False otherwise.
            :raises: InvalidLdapParameterException if any attributes or values are malformed.
            :raises: ObjectNotFoundException if a distinguished name is specified and cannot be found
            :raises: AttributeModificationException if raise_exception_on_failure is True and we fail
            :raises: Other LDAP exceptions from the ldap3 library if the connection is configured to raise exceptions and
                     issues are seen such as determining that a value is malformed based on the server schema.

        atomic_append_to_attribute_for_user(self, user: Union[str, ms_active_directory.core.ad_objects.ADUser], attribute: str, value, controls: List[ldap3.protocol.rfc4511.Control] = None, raise_exception_on_failure: bool = True, skip_validation: bool = False) -> bool
            Atomically append a value to an attribute for a user in the domain.

            :param user: Either an ADUser object or string name referencing the user to be modified.
            :param attribute: A string specifying the name of the LDAP attribute to be appended to.
            :param value: The value to append to the attribute. Value may either be a primitive, such as a string, bytes,
                          or a number, if a single value will be appended. Value may also be an iterable such as a set or
                          a list if a multi-valued attribute will be appended to, in order to append multiple new values
                          to it at once.
            :param controls: LDAP controls to use during the modification operation.
            :param raise_exception_on_failure: If true, an exception will be raised with additional details if the modify
                                               fails.
            :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                    Defaults to False. This can be used to make this function more performant when
                                    the caller knows all the distinguished names being specified are valid, as it
                                    performs far fewer queries.
            :returns: True if the operation succeeds, False otherwise.
            :raises: InvalidLdapParameterException if any attributes or values are malformed.
            :raises: ObjectNotFoundException if a distinguished name is specified and cannot be found
            :raises: AttributeModificationException if raise_exception_on_failure is True and we fail
            :raises: Other LDAP exceptions from the ldap3 library if the connection is configured to raise exceptions and
                     issues are seen such as determining that a value is malformed based on the server schema.

        atomic_append_to_attributes_for_computer(self, computer: Union[str, ms_active_directory.core.ad_objects.ADComputer], attribute_to_value_map: dict, controls: List[ldap3.protocol.rfc4511.Control] = None, raise_exception_on_failure: bool = True, skip_validation: bool = False) -> bool
            Atomically append values to multiple attributes for a computer in the domain.

            :param computer: Either an ADComputer object or string name referencing the computer to be modified.
            :param attribute_to_value_map: A dictionary mapping string LDAP attribute names to values that will be used
                                           in the modification operation. Values may either be primitives, such as strings,
                                           bytes, and numbers if a single value will be appended. Values may
                                           also be iterables such as sets and lists if multiple values will be appended
                                           to the attributes.
            :param controls: LDAP controls to use during the modification operation.
            :param raise_exception_on_failure: If true, an exception will be raised with additional details if the modify
                                               fails.
            :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                    Defaults to False. This can be used to make this function more performant when
                                    the caller knows all the distinguished names being specified are valid, as it
                                    performs far fewer queries.
            :returns: True if the operation succeeds, False otherwise.
            :raises: InvalidLdapParameterException if any attributes or values are malformed.
            :raises: ObjectNotFoundException if a distinguished name is specified and cannot be found
            :raises: AttributeModificationException if raise_exception_on_failure is True and we fail
            :raises: Other LDAP exceptions from the ldap3 library if the connection is configured to raise exceptions and
                     issues are seen such as determining that a value is malformed based on the server schema.

        atomic_append_to_attributes_for_group(self, group: Union[str, ms_active_directory.core.ad_objects.ADGroup], attribute_to_value_map: dict, controls: List[ldap3.protocol.rfc4511.Control] = None, raise_exception_on_failure: bool = True, skip_validation: bool = False) -> bool
            Atomically append values to multiple attributes for a group in the domain.

            :param group: Either an ADGroup object or string name referencing the group to be modified.
            :param attribute_to_value_map: A dictionary mapping string LDAP attribute names to values that will be used
                                           in the modification operation. Values may either be primitives, such as strings,
                                           bytes, and numbers if a single value will be appended. Values may
                                           also be iterables such as sets and lists if multiple values will be appended
                                           to the attributes.
            :param controls: LDAP controls to use during the modification operation.
            :param raise_exception_on_failure: If true, an exception will be raised with additional details if the modify
                                               fails.
            :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                    Defaults to False. This can be used to make this function more performant when
                                    the caller knows all the distinguished names being specified are valid, as it
                                    performs far fewer queries.
            :returns: True if the operation succeeds, False otherwise.
            :raises: InvalidLdapParameterException if any attributes or values are malformed.
            :raises: ObjectNotFoundException if a distinguished name is specified and cannot be found
            :raises: AttributeModificationException if raise_exception_on_failure is True and we fail
            :raises: Other LDAP exceptions from the ldap3 library if the connection is configured to raise exceptions and
                     issues are seen such as determining that a value is malformed based on the server schema.

        atomic_append_to_attributes_for_object(self, ad_object: Union[str, ms_active_directory.core.ad_objects.ADObject], attribute_to_value_map: dict, controls: List[ldap3.protocol.rfc4511.Control] = None, raise_exception_on_failure: bool = True, skip_validation: bool = False) -> bool
            Atomically append values to multiple attributes for an object in the domain.

            :param ad_object: Either an ADObject object or string distinguished name referencing the object to be modified.
            :param attribute_to_value_map: A dictionary mapping string LDAP attribute names to values that will be used
                                           in the modification operation. Values may either be primitives, such as strings,
                                           bytes, and numbers if a single value will be appended. Values may
                                           also be iterables such as sets and lists if multiple values will be appended
                                           to the attributes.
            :param controls: LDAP controls to use during the modification operation.
            :param raise_exception_on_failure: If true, an exception will be raised with additional details if the modify
                                               fails.
            :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                    Defaults to False. This can be used to make this function more performant when
                                    the caller knows all the distinguished names being specified are valid, as it
                                    performs far fewer queries.
            :returns: True if the operation succeeds, False otherwise.
            :raises: InvalidLdapParameterException if any attributes or values are malformed.
            :raises: ObjectNotFoundException if a distinguished name is specified and cannot be found
            :raises: AttributeModificationException if raise_exception_on_failure is True and we fail
            :raises: Other LDAP exceptions from the ldap3 library if the connection is configured to raise exceptions and
                     issues are seen such as determining that a value is malformed based on the server schema.

        atomic_append_to_attributes_for_user(self, user: Union[str, ms_active_directory.core.ad_objects.ADUser], attribute_to_value_map: dict, controls: List[ldap3.protocol.rfc4511.Control] = None, raise_exception_on_failure: bool = True, skip_validation: bool = False) -> bool
            Atomically append values to multiple attributes for a user in the domain.

            :param user: Either an ADUser object or string name referencing the user to be modified.
            :param attribute_to_value_map: A dictionary mapping string LDAP attribute names to values that will be used
                                           in the modification operation. Values may either be primitives, such as strings,
                                           bytes, and numbers if a single value will be appended. Values may
                                           also be iterables such as sets and lists if multiple values will be appended
                                           to the attributes.
            :param controls: LDAP controls to use during the modification operation.
            :param raise_exception_on_failure: If true, an exception will be raised with additional details if the modify
                                               fails.
            :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                    Defaults to False. This can be used to make this function more performant when
                                    the caller knows all the distinguished names being specified are valid, as it
                                    performs far fewer queries.
            :returns: True if the operation succeeds, False otherwise.
            :raises: InvalidLdapParameterException if any attributes or values are malformed.
            :raises: ObjectNotFoundException if a distinguished name is specified and cannot be found
            :raises: AttributeModificationException if raise_exception_on_failure is True and we fail
            :raises: Other LDAP exceptions from the ldap3 library if the connection is configured to raise exceptions and
                     issues are seen such as determining that a value is malformed based on the server schema.

        change_password_for_account(self, account: Union[str, ms_active_directory.core.ad_objects.ADUser, ms_active_directory.core.ad_objects.ADComputer], new_password: str, current_password: str, skip_validation: bool = False) -> bool
            Change a password for a user (includes computers) given the new desired password and old desired password.
            When a password is changed, the old password is provided along with the new one, and this significantly reduces
            the permissions needed in order to perform the operation. By default, any user can perform CHANGE_PASSWORD for
            any other user.
            This also avoids invalidating kerberos keys generated by the old password. Their validity will depend on the
            domain's policy regarding old passwords/keys and their allowable use period after change.

            :param account: The account whose password is being changed. This may either be a string account name, to be
                            looked up, or an ADObject object.
            :param current_password: The current password for the account.
            :param new_password: The new password for the account. Technically, if None is specified, then this behaves
                                 as a RESET_PASSWORD operation.
            :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                    Defaults to False. This can be used to make this function more performant when
                                    the caller knows all the distinguished names being specified are valid, as it
                                    performs far fewer queries.
            :returns: True if the operation succeeds. If the operation fails, either an exception will be raised or False
                      will be returned depending on whether the ldap connection for this session has "raise_exceptions"
                      set to True or not.

        create_computer(self, computer_name: str, computer_location: str = None, computer_password: str = None, encryption_types: List[Union[str, ms_active_directory.environment.security.security_config_constants.ADEncryptionType]] = None, hostnames: List[str] = None, services: List[str] = None, supports_legacy_behavior: bool = False, **additional_account_attributes) -> ms_active_directory.core.managed_ad_objects.ManagedADComputer
            Use the session to create a computer in the domain and return a computer object.
            :param computer_name: The common name of the computer to create in the AD domain. This
                                  will be used to determine the sAMAccountName, and if no hostnames
                                  are specified then this will be used to determine the hostnames for
                                  the computer.
            :param computer_location: The distinguished name of the location within the domain where
                                      the computer will be created. It may be a relative distinguished
                                      name (not including the domain component) or a full distinguished
                                      name.  If not specified, defaults to CN=Computers which is
                                      standard for Active Directory.
            :param computer_password: The password to be set for the computer. This is particularly
                                      useful to specify if the computer will be shared across multiple
                                      applications or devices, or if pre-creating a computer for another
                                      application to use. If not specified, a random 120 character
                                      password will be generated.
            :param encryption_types: The encryption types to set as supported on the computer in AD.
                                     These will also be used to generate kerberos keys for the computer.
                                     If not specified, defaults to [aes256-cts-hmac-sha1-96].
            :param hostnames: The hostnames to use for configuring the service principal names of the
                              computer. These may be short hostnames or fully qualified domain names.
                              If not specified, defaults to the "computer_name" as a short hostname and
                              "computer_name.domain" as a fully qualified domain name.
            :param services: The services to enable on each hostname, which will be used with hostnames
                             to generate the computer's service principal names. If not specified,
                             defaults to ["HOST"] which is standard for Active Directory.
            :param supports_legacy_behavior: Does the computer being created support legacy behavior such
                                             as NTLM authentication or UNC path addressing from older windows
                                             clients? Defaults to False. Impacts the restrictions on
                                             computer naming.
            :param additional_account_attributes: Additional LDAP attributes to set on the account and their
                                                  values. This is used to support power users setting arbitrary
                                                  attributes, such as "userCertificate" to set the certificate
                                                  for a computer that will use mutual TLS for EXTERNAL SASL auth.
                                                  This also allows overriding of some values that are not explicit
                                                  keyword arguments in order to avoid over-complication, since most
                                                  people won't set them (e.g. userAccountControl).
            :returns: an ManagedADComputer object representing the computer.
            :raises: DomainJoinException if any of our validation of the specified attributes fails or if anything
                     specified conflicts with objects in the domain.
            :raises: ObjectCreationException if we fail to create the computer for a reason unrelated to what we can
                     easily validate in advance (e.g. permission issue)

        create_transfer_sessions_to_all_trusted_domains(self, ignore_and_remove_failed_transfers=False) -> List[ForwardRef('ADSession')]
            Create transfer sessions to all of the different active directory domains that trust the domain used for
            this session.

            :param ignore_and_remove_failed_transfers: If true, failures to transfer the session to a trusted domain will
                                                       be ignored, and will be excluded from results. If false, errors will
                                                       be raised by failed transfers. Defaults to false.
            :returns: A list of ADSession objects representing the transferred authentication to the trusted domains.
            :raises: Other LDAP exceptions if the attempt to bind the transfer session in the trusted domain fails due to
                     authentication issues (e.g. trying to use a non-transitive trust when transferring a user that is
                     not from the primary domain, transferring across a one-way trust when skipping validation,
                     transferring to a domain using SID filtering to restrict cross-domain users)

        disable_account(self, account: Union[str, ms_active_directory.core.ad_objects.ADUser, ms_active_directory.core.ad_objects.ADComputer]) -> bool
            Disable a user account.
            :param account: The string name of the user/computer account to disable. This may either be a
                            sAMAccountName, a distinguished name, or a unique common name. This can also be an ADObject,
                            and the distinguished name will be extracted from it.
            :returns: True if the operation succeeds. If the operation fails, either an exception will be raised or False
                      will be returned depending on whether the ldap connection for this session has "raise_exceptions"
                      set to True or not.

        dn_exists_in_domain(self, distinguished_name: str) -> bool
            Check if a distinguished name exists within the domain, regardless of what it is.
            :param distinguished_name: Either a relative distinguished name or full distinguished name
                                       to search for within the domain.
            :returns: True if the distinguished name exists within the domain.

        enable_account(self, account: Union[str, ms_active_directory.core.ad_objects.ADComputer, ms_active_directory.core.ad_objects.ADUser]) -> bool
            Enable a user account.
            :param account: The string name of the user/computer account to enable. This may either be a
                            sAMAccountName, a distinguished name, or a unique common name. This can also be an ADObject,
                            and the distinguished name will be extracted from it.
            :returns: True if the operation succeeds. If the operation fails, either an exception will be raised or False
                      will be returned depending on whether the ldap connection for this session has "raise_exceptions"
                      set to True or not.

        find_certificate_authorities_for_domain(self, pem_format: bool = True, controls: List[ldap3.protocol.rfc4511.Control] = None) -> Union[List[str], List[bytes]]
            Attempt to discover the CAs within the domain and return info on their certificates.
            If a session was first established using an IP address or blind trust TLS, but we want to bootstrap our
            sessions to establish stronger trust, or write the CA certificates to a local truststore for other
            non-LDAP applications to use (e.g. establishing roots of trust for https or syslog over TLS), then it's
            helpful to grab the certificate authorities in the domain and their signing certificates.
            Not all domains run certificate authorities; some use public CAs or get certs from other PKI being run,
            so this isn't useful for everyone. But a lot of people do run CAs in their AD domains, and this is useful
            for them.

            :param pem_format: If True, return the certificates as strings in PEM format. Otherwise, return the
                               certificates as bytestrings in DER format. Defaults to True.
            :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                             whether or not certain properties/attributes are critical, which influences whether a search
                             may succeed or fail based on their availability.
            :returns: A list of either PEM-formatted certificate strings or DER-formatted certificate byte strings,
                      representing the CA certificates of the CAs within the domain.

        find_computer_by_distinguished_name(self, computer_dn: str, attributes_to_lookup: List[str] = None, controls: List[ldap3.protocol.rfc4511.Control] = None) -> Union[ms_active_directory.core.ad_objects.ADComputer, NoneType]
            Find a Computer in AD based on a specified distinguished name and return it along with any
            requested attributes.
            :param computer_dn: The distinguished name of the computer.
            :param attributes_to_lookup: A list of additional LDAP attributes to query for the computer. Regardless of
                                         what's specified, the computer's name and object class attributes will be queried.
            :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                             whether or not certain properties/attributes are critical, which influences whether a search
                             may succeed or fail based on their availability.
            :returns: an ADComputer object or None if the computer does not exist.

        find_computer_by_name(self, computer_name: str, attributes_to_lookup: List[str] = None, controls: List[ldap3.protocol.rfc4511.Control] = None) -> Union[ms_active_directory.core.ad_objects.ADComputer, NoneType]
            Find a Computer in AD based on a provided name.
            This function takes in a generic name which can be either a distinguished name, a common name, or a
            sAMAccountName, and tries to find a unique computer identified by it and return information on the computer.
            :param computer_name: The name of the computer, which may be a DN, common name, or sAMAccountName.
            :param attributes_to_lookup: A list of additional LDAP attributes to query for the computer. Regardless of
                                         what's specified, the computer's name and object class attributes will be queried.
            :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                             whether or not certain properties/attributes are critical, which influences whether a search
                             may succeed or fail based on their availability.
            :returns: an ADComputer object or None if the computer does not exist.
            :raises: a DuplicateNameException if more than one entry exists with this name.

        find_computer_by_sam_name(self, computer_name: str, attributes_to_lookup: List[str] = None, controls: List[ldap3.protocol.rfc4511.Control] = None) -> Union[ms_active_directory.core.ad_objects.ADComputer, NoneType]
            Find a Computer in AD based on a specified sAMAccountName name and return it along with any
            requested attributes.
            :param computer_name: The sAMAccountName name of the computer. Because a lot of people get a bit confused on
                                  what a computer name, as many systems leave out the trailing $ that's common to many
                                  computer sAMAccountNames when showing it, if computer_name does not end in a trailing $
                                  and no computer can be found with computer_name, a lookup will be attempted for the
                                  computer_name with a trailing $ added.
            :param attributes_to_lookup: A list of additional LDAP attributes to query for the computer. Regardless of
                                         what's specified, the computer's name and object class attributes will be queried.
            :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                             whether or not certain properties/attributes are critical, which influences whether a search
                             may succeed or fail based on their availability.
            :returns: an ADComputer object or None if the computer does not exist.

        find_computer_by_sid(self, computer_sid: Union[ms_active_directory.environment.security.security_config_constants.WellKnownSID, str, ms_active_directory.environment.security.security_descriptor_utils.ObjectSid], attributes_to_lookup: List[str] = None, controls: List[ldap3.protocol.rfc4511.Control] = None) -> Union[ms_active_directory.core.ad_objects.ADComputer, NoneType]
            Find a Computer in AD given its SID.
            This function takes in a computer's objectSID and then looks up the computer in AD using it. SIDs are unique
            so only a single entry can be found at most.
            The computer SID can be in many formats (well known SID enum, ObjectSID object, canonical SID format,
            or bytes) and so all 4 possible formats are handled.
            :param computer_sid: The computer SID. This may either be a well-known SID enum, an ObjectSID object, a string
                                 SID in canonical format (e.g. S-1-1-0), object SID bytes, or the hex representation of
                                 such bytes.
            :param attributes_to_lookup: A list of additional LDAP attributes to query for the computer. Regardless of
                                         what's specified, the computer's name and object class attributes will be queried.
            :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                             whether or not certain properties/attributes are critical, which influences whether a search
                             may succeed or fail based on their availability.
            :returns: an ADComputer object or None if the computer does not exist.

        find_computers_by_attribute(self, attribute_name: str, attribute_value, attributes_to_lookup: List[str] = None, size_limit: int = 0, controls: List[ldap3.protocol.rfc4511.Control] = None) -> List[ms_active_directory.core.ad_objects.ADComputer]
            Find all computers that possess the specified attribute with the specified value, and return a list of
            ADComputer objects.

            :param attribute_name: The LDAP name of the attribute to be used in the search.
            :param attribute_value: The value that returned computers should possess for the attribute.
            :param attributes_to_lookup: A list of additional LDAP attributes to query for the computers. Regardless of
                                         what's specified, the computers' name and object class attributes will be queried.
            :param size_limit: An integer indicating a limit to place the number of results the search will return.
                               If not specified, defaults to 0, meaning unlimited.
            :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                             whether or not certain properties/attributes are critical, which influences whether a search
                             may succeed or fail based on their availability.
            :returns: a list of ADComputer objects representing computers with the specified value for the specified
                      attribute.

        find_computers_by_common_name(self, computer_name: str, attributes_to_lookup: List[str] = None, controls: List[ldap3.protocol.rfc4511.Control] = None) -> List[ms_active_directory.core.ad_objects.ADComputer]
            Find all computers with a given common name and return a list of ADComputer objects.
            This is particularly useful when you have multiple computers with the same name in different OUs
            as a result of a migration, and want to find them so you can combine them.

            :param computer_name: The common name of the computer(s) to be looked up.
            :param attributes_to_lookup: A list of additional LDAP attributes to query for the computers. Regardless of
                                         what's specified, the computers' name and object class attributes will be queried.
            :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                             whether or not certain properties/attributes are critical, which influences whether a search
                             may succeed or fail based on their availability.
            :returns: a list of ADComputer objects representing computers with the specified common name.

        find_current_time_for_domain(self) -> datetime.datetime
            Get the current time for the domain as a datetime object.
            Just calls the parent domain function and returns that. This is included here for completeness.
            :returns: A datetime object representing the current time in the domain.

        find_dns_servers_for_domain(self, controls: List[ldap3.protocol.rfc4511.Control] = None) -> Dict[str, str]
            Attempt to discover the DNS servers within the domain and return info on them.
            If a session was first established using an IP address or blind trust TLS, but we want to bootstrap our
            sessions to use kerberos or TLS backed by CA certificates, we need proper DNS configured. For private
            domains (e.g. in a datacenter), we may run DNS servers within the domain. This function discovers
            computers with a "DNS/" service principal name, tries to look up IP addresses for them, and then
            returns that information.
            This won't always be useful, as DNS isn't always part of the AD domain, but it can help if we're bootstrapping
            a computer with manufacturer configurations to use the AD domain for everything based on a minimal starting
            configuration.

            :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                             whether or not certain properties/attributes are critical, which influences whether a search
                             may succeed or fail based on their availability.
            :returns: A dictionary mapping DNS hostnames of DNS servers to IP addresses. The hostnames are provided in case
                      a caller is configuring DNS-over-TLS. If no IP address can be resolved for a hostname, it will map to
                      a None value.
                      https://datatracker.ietf.org/doc/html/rfc8310

        find_forest_schema_version(self) -> ms_active_directory.environment.constants.ADVersion
            Attempt to determine the version of Windows Server set in the forest's schema.
            :returns: An Enum of type ADVersion indicating the schema version.

        find_functional_level_for_domain(self) -> ms_active_directory.environment.constants.ADFunctionalLevel
            Attempt to discover the functional level of the domain and return it.
            This will indicate if the domain is operating at the level of a 2008, 2012R2, 2016, etc. domain.
            The functional level of a domain influences what functionality exists (e.g. 2003 cannot issue AES keys,
            2012 cannot use many TLS ciphers introduced with TLS1.3) and so it can be useful for determining what
            to do.
            :returns: An Enum of type ADFunctionalLevel indicating the functional level.

        find_group_by_distinguished_name(self, group_dn: str, attributes_to_lookup: List[str] = None, controls: List[ldap3.protocol.rfc4511.Control] = None) -> Union[ms_active_directory.core.ad_objects.ADGroup, NoneType]
            Find a group in AD based on a specified distinguished name and return it along with any
            requested attributes.
            :param group_dn: The distinguished name of the group.
            :param attributes_to_lookup: A list of additional LDAP attributes to query for the group. Regardless of
                                         what's specified, the group's name and object class attributes will be queried.
            :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                             whether or not certain properties/attributes are critical, which influences whether a search
                             may succeed or fail based on their availability.
            :returns: an ADGroup object or None if the group does not exist.

        find_group_by_name(self, group_name: str, attributes_to_lookup: List[str] = None, controls: List[ldap3.protocol.rfc4511.Control] = None) -> Union[ms_active_directory.core.ad_objects.ADGroup, NoneType]
            Find a Group in AD based on a provided name.
            This function takes in a generic name which can be either a distinguished name, a common name, or a
            sAMAccountName, and tries to find a unique group identified by it and return information on the group.
            :param group_name: The name of the group, which may be a DN, common name, or sAMAccountName.
            :param attributes_to_lookup: A list of additional LDAP attributes to query for the group. Regardless of
                                         what's specified, the group's name and object class attributes will be queried.
            :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                             whether or not certain properties/attributes are critical, which influences whether a search
                             may succeed or fail based on their availability.
            :returns: an ADGroup object or None if the group does not exist.
            :raises: a DuplicateNameException if more than one entry exists with this name.

        find_group_by_sam_name(self, group_name: str, attributes_to_lookup: List[str] = None, controls: List[ldap3.protocol.rfc4511.Control] = None) -> Union[ms_active_directory.core.ad_objects.ADGroup, NoneType]
            Find a Group in AD based on a specified sAMAccountName name and return it along with any
            requested attributes.
            :param group_name: The sAMAccountName name of the group.
            :param attributes_to_lookup: A list of additional LDAP attributes to query for the group. Regardless of
                                         what's specified, the group's name and object class attributes will be queried.
            :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                             whether or not certain properties/attributes are critical, which influences whether a search
                             may succeed or fail based on their availability.
            :returns: an ADGroup object or None if the group does not exist.

        find_group_by_sid(self, group_sid: Union[ms_active_directory.environment.security.security_config_constants.WellKnownSID, str, ms_active_directory.environment.security.security_descriptor_utils.ObjectSid], attributes_to_lookup: List[str] = None, controls: List[ldap3.protocol.rfc4511.Control] = None) -> Union[ms_active_directory.core.ad_objects.ADGroup, NoneType]
            Find a Group in AD given its SID.
            This function takes in a group's objectSID and then looks up the group in AD using it. SIDs are unique
            so only a single entry can be found at most.
            The group SID can be in many formats (well known SID enum, ObjectSID object, canonical SID format,
            or bytes) and so all 4 possible formats are handled.
            :param group_sid: The group SID. This may either be a well-known SID enum, an ObjectSID object, a string SID
                              in canonical format (e.g. S-1-1-0), object SID bytes, or the hex representation of such bytes.
            :param attributes_to_lookup: A list of additional LDAP attributes to query for the group. Regardless of
                                         what's specified, the group's name and object class attributes will be queried.
            :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                             whether or not certain properties/attributes are critical, which influences whether a search
                             may succeed or fail based on their availability.
            :returns: an ADGroup object or None if the group does not exist.

        find_groups_by_attribute(self, attribute_name: str, attribute_value, attributes_to_lookup: List[str] = None, size_limit: int = 0, controls: List[ldap3.protocol.rfc4511.Control] = None) -> List[ms_active_directory.core.ad_objects.ADGroup]
            Find all groups that possess the specified attribute with the specified value, and return a list of ADGroup
            objects.

            :param attribute_name: The LDAP name of the attribute to be used in the search.
            :param attribute_value: The value that returned groups should possess for the attribute.
            :param attributes_to_lookup: A list of additional LDAP attributes to query for the group. Regardless of
                                         what's specified, the groups' name and object class attributes will be queried.
            :param size_limit: An integer indicating a limit to place the number of results the search will return.
                               If not specified, defaults to 0, meaning unlimited.
            :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                             whether or not certain properties/attributes are critical, which influences whether a search
                             may succeed or fail based on their availability.
            :returns: a list of ADGroup objects representing groups with the specified value for the specified attribute.

        find_groups_by_common_name(self, group_name: str, attributes_to_lookup: List[str] = None, controls: List[ldap3.protocol.rfc4511.Control] = None) -> List[ms_active_directory.core.ad_objects.ADGroup]
            Find all groups with a given common name and return a list of ADGroup objects.
            This is particularly useful when you have multiple groups with the same name in different OUs
            as a result of a migration, and want to find them so you can combine them.

            :param group_name: The common name of the group(s) to be looked up.
            :param attributes_to_lookup: A list of additional LDAP attributes to query for the group. Regardless of
                                         what's specified, the groups' name and object class attributes will be queried.
            :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                             whether or not certain properties/attributes are critical, which influences whether a search
                             may succeed or fail based on their availability.
            :returns: a list of ADGroup objects representing groups with the specified common name.

        find_groups_for_computer(self, computer: Union[str, ms_active_directory.core.ad_objects.ADComputer], attributes_to_lookup: List[str] = None, controls: List[ldap3.protocol.rfc4511.Control] = None, skip_validation: bool = False) -> List[ms_active_directory.core.ad_objects.ADGroup]
            Find the groups that a computer belongs to, look up attributes of theirs, and return information about them.

            :param computer: The computer to lookup group memberships for. This can either be an ADComputer or a string
                            name of an AD computer. If it is a string, the computer will be looked up first to get unique
                            distinguished name information about it unless it is a distinguished name.
            :param attributes_to_lookup: A list of string LDAP attributes to look up in addition to our basic attributes.
            :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                             whether or not certain properties/attributes are critical, which influences whether a search
                             may succeed or fail based on their availability.
            :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                    Defaults to False. This can be used to make this function more performant when
                                    the caller knows all the distinguished names being specified are valid, as it
                                    performs far fewer queries.
            :returns: A list of ADGroup objects representing the groups that this user belongs to.
            :raises: a DuplicateNameException if a computer name is specified and more than one entry exists with the name.
            :raises: a InvalidLdapParameterException if the computer name is not a string or ADComputer.

        find_groups_for_computers(self, computers: List[Union[str, ms_active_directory.core.ad_objects.ADComputer]], attributes_to_lookup: List[str] = None, controls: List[ldap3.protocol.rfc4511.Control] = None, skip_validation: bool = False) -> Dict[Union[str, ms_active_directory.core.ad_objects.ADComputer], List[ms_active_directory.core.ad_objects.ADGroup]]
            Find the groups that a list of computers belong to, look up attributes of theirs, and return information
            about them.

            :param computers: The computers to lookup group memberships for. This can be a list of either ADComputer objects
                              or string names of AD computers. If they are strings, the computers will be looked up first
                              to get unique distinguished name information about them unless they are distinguished names.
            :param attributes_to_lookup: A list of string LDAP attributes to look up in addition to our basic attributes.
            :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                             whether or not certain properties/attributes are critical, which influences whether a search
                             may succeed or fail based on their availability.
            :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                    Defaults to False. This can be used to make this function more performant when
                                    the caller knows all the distinguished names being specified are valid, as it
                                    performs far fewer queries.
            :returns: A dictionary mapping computers to lists of ADGroup objects representing the groups that they belong to
            :raises: a DuplicateNameException if a computer name is specified and more than one entry exists with the name.
            :raises: a InvalidLdapParameterException if any computers are not a string or ADComputer.

        find_groups_for_entities(self, entities: List[Union[str, ms_active_directory.core.ad_objects.ADObject]], attributes_to_lookup: List[str] = None, lookup_by_name_fn: <built-in function callable> = None, controls: List[ldap3.protocol.rfc4511.Control] = None, skip_validation: bool = False) -> Dict[Union[str, ms_active_directory.core.ad_objects.ADObject], List[ms_active_directory.core.ad_objects.ADGroup]]
            Find the parent groups for all of the entities in a List.
            These entities may be users, groups, or anything really because Active Directory uses the "groupOfNames" style
            membership tracking, so all group members are just represented as distinguished names regardless of type.
            If the elements of entities are strings and are not distinguished names, then lookup_by_name_fn will be used
            to look up the appropriate ADObject for the entity and get its distinguished name.

            The parent groups of all the entities will then be queried, and the attributes specified will be looked up
            (if any). A dictionary mapping the original entities to lists of ADGroup objects will be returned.

            :param entities: A list of either ADObject objects or strings. These represent the objects whose parent groups
                             are being queried.
            :param attributes_to_lookup: A list of LDAP attributes to query about the parent groups, in addition to the
                                         default ones queries. Optional.
            :param lookup_by_name_fn: An optional function to call to map entities to ADObjects when the members of entities
                                      are strings that are not LDAP distinguished names.
            :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                             whether or not certain properties/attributes are critical, which influences whether a search
                             may succeed or fail based on their availability.
            :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                    Defaults to False. This can be used to make this function more performant when
                                    the caller knows all the distinguished names being specified are valid, as it
                                    performs far fewer queries.
            :returns: A dictionary mapping input entities to lists of ADGroup object representing their parent groups.
            :raises: a DuplicateNameException if an entity name is specified and more than one entry exists with the name.
            :raises: InvalidLdapParameterException if any non-string non-ADObject types are found in entities, or if any
                     non-distinguished name strings are specified.

        find_groups_for_group(self, group: Union[str, ms_active_directory.core.ad_objects.ADGroup], attributes_to_lookup: List[str] = None, controls: List[ldap3.protocol.rfc4511.Control] = None, skip_validation: bool = False) -> List[ms_active_directory.core.ad_objects.ADGroup]
            Find the groups that a group belongs to, look up attributes of theirs, and return information about them.

            :param group: The group to lookup group memberships for. This can either be an ADGroup or a string name of an
                          AD group. If it is a string, the group will be looked up first to get unique distinguished name
                          information about it unless it is a distinguished name.
            :param attributes_to_lookup: A list of string LDAP attributes to look up in addition to our basic attributes.
            :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                             whether or not certain properties/attributes are critical, which influences whether a search
                             may succeed or fail based on their availability.
            :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                    Defaults to False. This can be used to make this function more performant when
                                    the caller knows all the distinguished names being specified are valid, as it
                                    performs far fewer queries.
            :returns: A list of ADGroup objects representing the groups that this group belongs to.
            :raises: a DuplicateNameException if a group name is specified and more than one entry exists with the name.
            :raises: a InvalidLdapParameterException if the group name is not a string or ADGroup.

        find_groups_for_groups(self, groups: List[Union[str, ms_active_directory.core.ad_objects.ADGroup]], attributes_to_lookup: List[str] = None, controls: List[ldap3.protocol.rfc4511.Control] = None, skip_validation: bool = False) -> Dict[Union[str, ms_active_directory.core.ad_objects.ADGroup], List[ms_active_directory.core.ad_objects.ADGroup]]
            Find the groups that a list of groups belong to, look up attributes of theirs, and return information about
            them.

            :param groups: The groups to lookup group memberships for. This can be a list of either ADGroup objects or
                           string names of AD groups. If they are strings, the groups will be looked up first to get unique
                           distinguished name information about them unless they are distinguished names.
            :param attributes_to_lookup: A list of string LDAP attributes to look up in addition to our basic attributes.
            :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                             whether or not certain properties/attributes are critical, which influences whether a search
                             may succeed or fail based on their availability.
            :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                    Defaults to False. This can be used to make this function more performant when
                                    the caller knows all the distinguished names being specified are valid, as it
                                    performs far fewer queries.
            :returns: A dictionary mapping groups to lists of ADGroup objects representing the groups that they belong to.
            :raises: a DuplicateNameException if a group name is specified and more than one entry exists with the name.
            :raises: a InvalidLdapParameterException if any groups are not a string or ADGroup.

        find_groups_for_user(self, user: Union[str, ms_active_directory.core.ad_objects.ADUser], attributes_to_lookup: List[str] = None, controls: List[ldap3.protocol.rfc4511.Control] = None, skip_validation: bool = False) -> List[ms_active_directory.core.ad_objects.ADGroup]
            Find the groups that a user belongs to, look up attributes of theirs, and return information about them.

            :param user: The user to lookup group memberships for. This can either be an ADUser or a string name of an
                         AD user. If it is a string, the user will be looked up first to get unique distinguished name
                         information about it unless it is a distinguished name.
            :param attributes_to_lookup: A list of string LDAP attributes to look up in addition to our basic attributes.
            :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                             whether or not certain properties/attributes are critical, which influences whether a search
                             may succeed or fail based on their availability.
            :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                    Defaults to False. This can be used to make this function more performant when
                                    the caller knows all the distinguished names being specified are valid, as it
                                    performs far fewer queries.
            :returns: A list of ADGroup objects representing the groups that this user belongs to.
            :raises: a DuplicateNameException if a user name is specified and more than one entry exists with the name.
            :raises: a InvalidLdapParameterException if the user name is not a string or ADUser.

        find_groups_for_users(self, users: List[Union[str, ms_active_directory.core.ad_objects.ADUser]], attributes_to_lookup: List[str] = None, controls: List[ldap3.protocol.rfc4511.Control] = None, skip_validation: bool = False) -> Dict[Union[str, ms_active_directory.core.ad_objects.ADUser], List[ms_active_directory.core.ad_objects.ADGroup]]
            Find the groups that a list of users belong to, look up attributes of theirs, and return information about
            them.

            :param users: The users to lookup group memberships for. This can be a list of either ADUser objects or
                          string names of AD users. If they are strings, the users will be looked up first to get unique
                          distinguished name information about them unless they are distinguished names.
            :param attributes_to_lookup: A list of string LDAP attributes to look up in addition to our basic attributes.
            :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                             whether or not certain properties/attributes are critical, which influences whether a search
                             may succeed or fail based on their availability.
            :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                    Defaults to False. This can be used to make this function more performant when
                                    the caller knows all the distinguished names being specified are valid, as it
                                    performs far fewer queries.
            :returns: A dictionary mapping users to lists of ADGroup objects representing the groups that they belong to.
            :raises: a DuplicateNameException if a user name is specified and more than one entry exists with the name.
            :raises: a InvalidLdapParameterException if any users are not a string or ADUser.

        find_members_of_group(self, group: Union[str, ms_active_directory.core.ad_objects.ADGroup], attributes_to_lookup: List[str] = None, controls: List[ldap3.protocol.rfc4511.Control] = None, skip_validation: bool = False) -> List[Union[ms_active_directory.core.ad_objects.ADUser, ms_active_directory.core.ad_objects.ADComputer, ms_active_directory.core.ad_objects.ADObject, ms_active_directory.core.ad_objects.ADGroup]]
            Find the members of a group in the domain, along with attributes of the members.

            :param group: Either a string name of a group or ADGroup to look up the members of.
            :param attributes_to_lookup: Attributes to look up about the members of each group.
            :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                             whether or not certain properties/attributes are critical, which influences whether a search
                             may succeed or fail based on their availability.
            :param skip_validation: If true, assume all members exist and do not raise an error if we fail to look one up.
                                    Instead, a placeholder object will be used for members that could not be found.
                                    Defaults to False.
            :return: A list of objects representing the group's members.
                     The objects may be of type ADUser, ADComputer, ADGroup, etc. - this function attempts to cast all
                     member objects to the most accurate object type representing them. ADObject will be used for members
                     that do not match any of the more specific object types in the library
                     (e.g. foreign security principals).
            :raises: InvalidLdapParameterException if the group is not a string or ADGroup
            :raises: ObjectNotFoundException if the group cannot be found.
            :raises: DomainSearchException if skip_validation is False and any group members cannot be found.

        find_members_of_group_recursive(self, group: Union[str, ms_active_directory.core.ad_objects.ADGroup], attributes_to_lookup: List[str] = None, controls: List[ldap3.protocol.rfc4511.Control] = None, skip_validation: bool = False, maximum_nesting_depth: int = None, flatten: bool = False) -> List[Dict[Union[str, ms_active_directory.core.ad_objects.ADGroup], List[ms_active_directory.core.ad_objects.ADGroup]]]
            Find the members of a group in the domain, along with attributes of the members.

            :param group: Either a string name of a group or ADGroup to look up the members of.
            :param attributes_to_lookup: Attributes to look up about the members of each group.
            :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                             whether or not certain properties/attributes are critical, which influences whether a search
                             may succeed or fail based on their availability.
            :param skip_validation: If true, assume all members exist and do not raise an error if we fail to look one up.
                                    Instead, a placeholder object will be used for members that could not be found.
                                    Defaults to False.
            :param maximum_nesting_depth: A limit to the number of levels of nesting to recurse beyond the first lookup.
                                          A level of 0 makes this behave the same as find_members_of_groups and a level of
                                          None means recurse until we've gone through all nesting. Defaults to None.
            :param flatten: If set to True, a 1-item list of a single dictionary mapping the input group to a list of
                            all members found recursively will be returned. This discards information about whether
                            a member is a direct member or is a member via nesting, and what those relationships are.
                            As an example, instead of returning [{group1 -> [group2, user1]}, {group2 -> [user2, user3]}],
                            we would return [{group1 -> [group2, user1, user2, user3]}]. This makes iterating members
                            simpler, but removes the ability to use information about the descendants of nested groups
                            as independent groups later on.
                            Defaults to False.
            :return: A list of dictionaries mapping groups to objects representing the group's members.
                     The first dictionary maps the input group to its members; the second dictionary maps the groups that
                     were members of the groups in the first dictionary to their members, and so on and so forth.
                     The objects may be of type ADUser, ADComputer, ADGroup, etc. - this function attempts to cast all
                     member objects to the most accurate object type representing them. ADObject will be used for members
                     that do not match any of the more specific object types in the library
                     (e.g. foreign security principals).
            :raises: InvalidLdapParameterException if the group is not a string or ADGroup
            :raises: ObjectNotFoundException if the group cannot be found.
            :raises: DomainSearchException if skip_validation is False and any group members cannot be found.

        find_members_of_groups(self, groups: List[Union[str, ms_active_directory.core.ad_objects.ADGroup]], attributes_to_lookup: List[str] = None, controls: List[ldap3.protocol.rfc4511.Control] = None, skip_validation: bool = False) -> Dict[Union[str, ms_active_directory.core.ad_objects.ADGroup], List[Union[ms_active_directory.core.ad_objects.ADUser, ms_active_directory.core.ad_objects.ADComputer, ms_active_directory.core.ad_objects.ADObject, ms_active_directory.core.ad_objects.ADGroup]]]
            Find the members of one or more groups in the domain, along with attributes of the members.

            :param groups: A list of either strings or ADGroups to look up the members of.
            :param attributes_to_lookup: Attributes to look up about the members of each group.
            :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                             whether or not certain properties/attributes are critical, which influences whether a search
                             may succeed or fail based on their availability.
            :param skip_validation: If true, assume all members exist and do not raise an error if we fail to look one up.
                                    Instead, a placeholder object will be used for members that could not be found.
                                    Defaults to False.
            :return: A dictionary mapping groups from the input list to lists of objects representing their members.
                     The objects may be of type ADUser, ADComputer, ADGroup, etc. - this function attempts to cast all
                     member objects to the most accurate object type representing them. ADObject will be used for members
                     that do not match any of the more specific object types in the library
                     (e.g. foreign security principals).
            :raises: InvalidLdapParameterException if any groups are not strings or ADGroups
            :raises: ObjectNotFoundException if any groups cannot be found.
            :raises: DomainSearchException if skip_validation is False and any group members cannot be found.

        find_members_of_groups_recursive(self, groups: List[Union[str, ms_active_directory.core.ad_objects.ADGroup]], attributes_to_lookup: List[str] = None, controls: List[ldap3.protocol.rfc4511.Control] = None, skip_validation: bool = False, maximum_nesting_depth: int = None) -> List[Dict[Union[str, ms_active_directory.core.ad_objects.ADGroup], List[ms_active_directory.core.ad_objects.ADGroup]]]
            Find the members of a group in the domain, along with attributes of the members.

            :param groups: Either a string name of a group or ADGroup to look up the members of.
            :param attributes_to_lookup: Attributes to look up about the members of each group.
            :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                             whether or not certain properties/attributes are critical, which influences whether a search
                             may succeed or fail based on their availability.
            :param skip_validation: If true, assume all members exist and do not raise an error if we fail to look one up.
                                    Instead, a placeholder object will be used for members that could not be found.
                                    Defaults to False.
            :param maximum_nesting_depth: A limit to the number of levels of nesting to recurse beyond the first lookup.
                                          A level of 0 makes this behave the same as find_members_of_groups and a level of
                                          None means recurse until we've gone through all nesting. Defaults to None.
            :return: A list of dictionaries mapping groups to objects representing the group's members.
                     The first dictionary maps the input groups to members; the second dictionary maps the groups that
                     were members of the groups in the first dictionary to their members, and so on and so forth.
                     The objects may be of type ADUser, ADComputer, ADGroup, etc. - this function attempts to cast all
                     member objects to the most accurate object type representing them. ADObject will be used for members
                     that do not match any of the more specific object types in the library
                     (e.g. foreign security principals).
            :raises: InvalidLdapParameterException if the group is not a string or ADGroup
            :raises: ObjectNotFoundException if the group cannot be found.
            :raises: DomainSearchException if skip_validation is False and any group members cannot be found.

        find_netbios_name_for_domain(self, force_refresh: bool = False) -> str
            Find the netbios name for this domain. Renaming a domain is a huge task and is incredibly rare,
            so this information is cached when first read, and it only re-read if specifically requested.

            :param force_refresh: If set to true, the domain will be searched for the information even if
                                  it is already cached. Defaults to false.
            :returns: A string indicating the netbios name of the domain.

        find_object_by_canonical_name(self, canonical_name: str, attributes_to_lookup: List[str] = None, controls: List[ldap3.protocol.rfc4511.Control] = None) -> Union[ms_active_directory.core.ad_objects.ADObject, ms_active_directory.core.ad_objects.ADUser, ms_active_directory.core.ad_objects.ADGroup, ms_active_directory.core.ad_objects.ADComputer, NoneType]
            Find an object in the domain using a canonical name, also called a 'windows path style' name.

            :param canonical_name: A windows path style name representing an object in the domain. This may be either a
                                   fully canonical name (e.g. example.com/Users/Administrator) or a relative canonical
                                   name (e.g. /Users/Administrator).
            :param attributes_to_lookup: Attributes to look up about the object. Regardless of what's specified,
                                         the object's name and object class attributes will be queried.
            :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                             whether or not certain properties/attributes are critical, which influences whether a search
                             may succeed or fail based on their availability.
            :returns: an ADObject object or None if the distinguished name does not exist. If the object can be cast to
                      a more specific subclass, like ADUser, then it will be.

        find_object_by_distinguished_name(self, distinguished_name: str, attributes_to_lookup: List[str] = None, controls: List[ldap3.protocol.rfc4511.Control] = None) -> Union[ms_active_directory.core.ad_objects.ADObject, ms_active_directory.core.ad_objects.ADUser, ms_active_directory.core.ad_objects.ADGroup, ms_active_directory.core.ad_objects.ADComputer, NoneType]
            Find an object in the domain using a relative distinguished name or full distinguished name.

            :param distinguished_name: A relative or absolute distinguished name within the domain to look up.
            :param attributes_to_lookup: Attributes to look up about the object. Regardless of what's specified,
                                         the object's name and object class attributes will be queried.
            :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                             whether or not certain properties/attributes are critical, which influences whether a search
                             may succeed or fail based on their availability.
            :returns: an ADObject object or None if the distinguished name does not exist. If the object can be cast to
                      a more specific subclass, like ADUser, then it will be.

        find_object_by_sid(self, sid: Union[ms_active_directory.environment.security.security_config_constants.WellKnownSID, str, ms_active_directory.environment.security.security_descriptor_utils.ObjectSid], attributes_to_lookup: List[str] = None, object_class: str = None, return_type=None, controls: List[ldap3.protocol.rfc4511.Control] = None) -> Union[ms_active_directory.core.ad_objects.ADObject, ms_active_directory.core.ad_objects.ADUser, ms_active_directory.core.ad_objects.ADGroup, ms_active_directory.core.ad_objects.ADComputer, NoneType]
            Find any object in AD given its SID.
            This function takes in a user's objectSID and then looks up the user in AD using it. SIDs are unique
            so only a single entry can be found at most.
            The user SID can be in many formats (well known SID enum, ObjectSID object, canonical SID format,
            or bytes) and so all 4 possible formats are handled.
            :param sid: The object's SID. This may either be a well-known SID enum, an ObjectSID object, a string SID
                        in canonical format (e.g. S-1-1-0), object SID bytes, or the hex representation of such bytes.
            :param attributes_to_lookup: A list of additional LDAP attributes to query for the object. Regardless of
                                         what's specified, the object's name and object class attributes will be queried.
            :param object_class: Optional. The object class to filter on when searching. Defaults to 'top' which will
                                 include all objects in AD.
            :param return_type: Optional. The class to use to represent the returned objects. Defaults to ADObject.
                                If a generic search is being done, or an object class is used that is not yet supported
                                by this library, using ADObject is recommended.
            :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                             whether or not certain properties/attributes are critical, which influences whether a search
                             may succeed or fail based on their availability.
            :returns: an ADObject object or None if the group does not exist.

        find_objects_with_attribute(self, attribute_name: str, attribute_value, attributes_to_lookup: List[str] = None, size_limit: int = 0, object_class: str = None, return_type=None, controls: List[ldap3.protocol.rfc4511.Control] = None) -> List[Union[ms_active_directory.core.ad_objects.ADUser, ms_active_directory.core.ad_objects.ADComputer, ms_active_directory.core.ad_objects.ADObject, ms_active_directory.core.ad_objects.ADGroup]]
            Find all AD objects that possess the specified attribute with the specified value and return them.

            :param attribute_name: The LDAP name of the attribute to be used in the search.
            :param attribute_value: The value that returned objects should possess for the attribute.
            :param attributes_to_lookup: A list of additional LDAP attributes to query for the group. Regardless of
                                         what's specified, the groups' name and object class attributes will be queried.
            :param size_limit: An integer indicating a limit to place the number of results the search will return.
                               If not specified, defaults to 0, meaning unlimited.
            :param object_class: Optional. The object class to filter on when searching. Defaults to 'top' which will
                                 include all objects in AD.
            :param return_type: Optional. The class to use to represent the returned objects. Defaults to ADObject.
                                If a generic search is being done, or an object class is used that is not yet supported
                                by this library, using ADObject is recommended.
            :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                             whether or not certain properties/attributes are critical, which influences whether a search
                             may succeed or fail based on their availability.
            :returns: a list of ADObject objects representing groups with the specified value for the specified attribute.

        find_security_descriptor_for_computer(self, computer: Union[str, ms_active_directory.core.ad_objects.ADComputer], include_sacl: bool = False, skip_validation: bool = False) -> ms_active_directory.environment.security.security_descriptor_utils.SelfRelativeSecurityDescriptor
            Given a computer, find its security descriptor. The security descriptor will be returned as a
            SelfRelativeSecurityDescriptor object.

            :param computer: The computer for which we will read the security descriptor. This may be an ADComputer object
                             or a string name identifying the computer (in which case it will be looked up).
            :param include_sacl: If true, we will attempt to read the System ACL for the user in addition to the
                                 Discretionary ACL and owner information when reading the security descriptor. This is
                                 more privileged than just getting the Discretionary ACL and owner information.
                                 Defaults to False.
            :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                    Defaults to False. This can be used to make this function more performant when
                                    the caller knows all the distinguished names being specified are valid, as it
                                    performs far fewer queries.
            :raises: ObjectNotFoundException if the computer cannot be found.
            :raises: InvalidLdapParameterException if the computer specified is not a string or an ADComputer object
            :raises: SecurityDescriptorDecodeException if we fail to decode the security descriptor.

        find_security_descriptor_for_group(self, group: Union[str, ms_active_directory.core.ad_objects.ADGroup], include_sacl: bool = False, skip_validation: bool = False) -> ms_active_directory.environment.security.security_descriptor_utils.SelfRelativeSecurityDescriptor
            Given a group, find its security descriptor. The security descriptor will be returned as a
            SelfRelativeSecurityDescriptor object.

            :param group: The group for which we will read the security descriptor. This may be an ADGroup object or a
                          string name identifying the group (in which case it will be looked up).
            :param include_sacl: If true, we will attempt to read the System ACL for the group in addition to the
                                 Discretionary ACL and owner information when reading the security descriptor. This is
                                 more privileged than just getting the Discretionary ACL and owner information.
                                 Defaults to False.
            :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                    Defaults to False. This can be used to make this function more performant when
                                    the caller knows all the distinguished names being specified are valid, as it
                                    performs far fewer queries.
            :raises: ObjectNotFoundException if the group cannot be found.
            :raises: InvalidLdapParameterException if the group specified is not a string or an ADGroup object
            :raises: SecurityDescriptorDecodeException if we fail to decode the security descriptor.

        find_security_descriptor_for_object(self, ad_object: Union[str, ms_active_directory.core.ad_objects.ADObject], include_sacl: bool = False, skip_validation: bool = False) -> ms_active_directory.environment.security.security_descriptor_utils.SelfRelativeSecurityDescriptor
            Given an object, find its security descriptor. The security descriptor will be returned as a
            SelfRelativeSecurityDescriptor object.

            :param ad_object: The object for which we will read the security descriptor. This may be an ADObject object or a
                              string distinguished identifying the object.
            :param include_sacl: If true, we will attempt to read the System ACL for the object in addition to the
                                 Discretionary ACL and owner information when reading the security descriptor. This is
                                 more privileged than just getting the Discretionary ACL and owner information.
                                 Defaults to False.
            :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                    Defaults to False. This can be used to make this function more performant when
                                    the caller knows all the distinguished names being specified are valid, as it
                                    performs far fewer queries.
            :raises: ObjectNotFoundException if the object cannot be found.
            :raises: InvalidLdapParameterException if the ad_object specified is not a string DN or an ADObject object
            :raises: SecurityDescriptorDecodeException if we fail to decode the security descriptor.

        find_security_descriptor_for_user(self, user: Union[str, ms_active_directory.core.ad_objects.ADUser], include_sacl: bool = False, skip_validation: bool = False) -> ms_active_directory.environment.security.security_descriptor_utils.SelfRelativeSecurityDescriptor
            Given a user, find its security descriptor. The security descriptor will be returned as a
            SelfRelativeSecurityDescriptor object.

            :param user: The user for which we will read the security descriptor. This may be an ADUser object or a
                         string name identifying the user (in which case it will be looked up).
            :param include_sacl: If true, we will attempt to read the System ACL for the user in addition to the
                                 Discretionary ACL and owner information when reading the security descriptor. This is
                                 more privileged than just getting the Discretionary ACL and owner information.
                                 Defaults to False.
            :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                    Defaults to False. This can be used to make this function more performant when
                                    the caller knows all the distinguished names being specified are valid, as it
                                    performs far fewer queries.
            :raises: ObjectNotFoundException if the user cannot be found.
            :raises: InvalidLdapParameterException if the user specified is not a string or an ADUser object
            :raises: SecurityDescriptorDecodeException if we fail to decode the security descriptor.

        find_supported_sasl_mechanisms_for_domain(self) -> List[str]
            Attempt to discover the SASL mechanisms supported by the domain and return them.
            This just builds upon the functionality that the domain has for this, as you don't need
            to be authenticated as anything other than anonymous to read this information (since it's
            often used to figure out how to authenticate).
            This is included in the session object for completeness.
            :returns: A list of strings indicating the supported SASL mechanisms for the domain.
                      ex: ['GSSAPI', 'GSS-SPNEGO', 'EXTERNAL']

        find_trusted_domains_for_domain(self, force_cache_refresh=False) -> List[ForwardRef('ADTrustedDomain')]
            Find the trusted domains for this domain.
            If we have cached trusted domains for this session's domain, and the cache is still valid based on our
            cache lifetime, return that.

            :param force_cache_refresh: If true, don't use our cached trusted domains even if the cache is valid.
                                        Defaults to false.
            :returns: A list of ADTrustedDomain objects

        find_user_by_distinguished_name(self, user_dn: str, attributes_to_lookup: List[str] = None, controls: List[ldap3.protocol.rfc4511.Control] = None) -> Union[ms_active_directory.core.ad_objects.ADUser, NoneType]
            Find a User in AD based on a specified distinguished name and return it along with any
            requested attributes.
            :param user_dn: The distinguished name of the user.
            :param attributes_to_lookup: A list of additional LDAP attributes to query for the user. Regardless of
                                         what's specified, the user's name and object class attributes will be queried.
            :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                             whether or not certain properties/attributes are critical, which influences whether a search
                             may succeed or fail based on their availability.
            :returns: an ADUser object or None if the user does not exist.

        find_user_by_name(self, user_name: str, attributes_to_lookup: List[str] = None, controls: List[ldap3.protocol.rfc4511.Control] = None) -> Union[ms_active_directory.core.ad_objects.ADUser, NoneType]
            Find a User in AD based on a provided name.
            This function takes in a generic name which can be either a distinguished name, a common name, or a
            sAMAccountName, and tries to find a unique user identified by it and return information on the user.
            :param user_name: The name of the user, which may be a DN, common name, or sAMAccountName.
            :param attributes_to_lookup: A list of additional LDAP attributes to query for the user. Regardless of
                                         what's specified, the user's name and object class attributes will be queried.
            :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                             whether or not certain properties/attributes are critical, which influences whether a search
                             may succeed or fail based on their availability.
            :returns: an ADUser object or None if the user does not exist.
            :raises: a DuplicateNameException if more than one entry exists with this name.

        find_user_by_sam_name(self, user_name: str, attributes_to_lookup: List[str] = None, controls: List[ldap3.protocol.rfc4511.Control] = None) -> Union[ms_active_directory.core.ad_objects.ADUser, NoneType]
            Find a User in AD based on a specified sAMAccountName name and return it along with any
            requested attributes.
            :param user_name: The sAMAccountName name of the user.
            :param attributes_to_lookup: A list of additional LDAP attributes to query for the user. Regardless of
                                         what's specified, the user's name and object class attributes will be queried.
            :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                             whether or not certain properties/attributes are critical, which influences whether a search
                             may succeed or fail based on their availability.
            :returns: an ADUser object or None if the user does not exist.

        find_user_by_sid(self, user_sid: Union[ms_active_directory.environment.security.security_config_constants.WellKnownSID, str, ms_active_directory.environment.security.security_descriptor_utils.ObjectSid], attributes_to_lookup: List[str] = None, controls: List[ldap3.protocol.rfc4511.Control] = None) -> Union[ms_active_directory.core.ad_objects.ADUser, NoneType]
            Find a User in AD given its SID.
            This function takes in a user's objectSID and then looks up the user in AD using it. SIDs are unique
            so only a single entry can be found at most.
            The user SID can be in many formats (well known SID enum, ObjectSID object, canonical SID format,
            or bytes) and so all 4 possible formats are handled.
            :param user_sid: The user SID. This may either be a well-known SID enum, an ObjectSID object, a string SID
                             in canonical format (e.g. S-1-1-0), object SID bytes, or the hex representation of such bytes.
            :param attributes_to_lookup: A list of additional LDAP attributes to query for the user. Regardless of
                                         what's specified, the user's name and object class attributes will be queried.
            :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                             whether or not certain properties/attributes are critical, which influences whether a search
                             may succeed or fail based on their availability.
            :returns: an ADUser object or None if the user does not exist.

        find_users_by_attribute(self, attribute_name: str, attribute_value, attributes_to_lookup: List[str] = None, size_limit: int = 0, controls: List[ldap3.protocol.rfc4511.Control] = None) -> List[ms_active_directory.core.ad_objects.ADUser]
            Find all users that possess the specified attribute with the specified value, and return a list of ADUser
            objects.

            :param attribute_name: The LDAP name of the attribute to be used in the search.
            :param attribute_value: The value that returned groups should possess for the attribute.
            :param attributes_to_lookup: A list of additional LDAP attributes to query for the users. Regardless of
                                         what's specified, the users' name and object class attributes will be queried.
            :param size_limit: An integer indicating a limit to place the number of results the search will return.
                               If not specified, defaults to 0, meaning unlimited.
            :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                             whether or not certain properties/attributes are critical, which influences whether a search
                             may succeed or fail based on their availability.
            :returns: a list of ADUser objects representing users with the specified value for the specified attribute.

        find_users_by_common_name(self, user_name: str, attributes_to_lookup: List[str] = None, controls: List[ldap3.protocol.rfc4511.Control] = None) -> List[ms_active_directory.core.ad_objects.ADUser]
            Find all users with a given common name and return a list of ADUser objects.
            This is particularly useful when you have multiple users with the same name in different OUs
            as a result of a migration, and want to find them so you can combine them.

            :param user_name: The common name of the user(s) to be looked up.
            :param attributes_to_lookup: A list of additional LDAP attributes to query for the users. Regardless of
                                         what's specified, the users' name and object class attributes will be queried.
            :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                             whether or not certain properties/attributes are critical, which influences whether a search
                             may succeed or fail based on their availability.
            :returns: a list of ADUser objects representing users with the specified common name.

        get_current_server_uri(self) -> str
            Returns the URI of the server that this session is currently communicating with

        get_domain(self) -> 'ADDomain'
            Returns the domain that this session is connected to

        get_domain_dns_name(self) -> str
            Returns the domain that this session is connected to

        get_domain_search_base(self) -> str
            Returns the LDAP search base used for all 'find' functions as the search base

        get_ldap_connection(self) -> ldap3.core.connection.Connection
            Returns the LDAP connection that this session uses for communication.
            This is particularly useful if a user wants to make complex LDAP queries or perform
            operations that are not supported by the ADSession object, and is willing to craft
            them and parse results themselves.

        get_search_paging_size(self) -> int

        get_trusted_domain_cache_lifetime_seconds(self) -> int

        is_authenticated(self) -> bool
            Returns if the session is currently authenticated

        is_domain_close_in_time_to_localhost(self, allowed_drift_seconds=None) -> bool
            Get whether the domain time is close to the current local time.
            Just calls the parent domain function and returns that. This is included here for completeness.
            :param allowed_drift_seconds: The number of seconds considered "close", defaults to 5 minutes.
                                          5 minutes is the standard allowable drift for kerberos.
            :returns: A boolean indicating whether we're within allowed_drift_seconds seconds of the domain time.

        is_encrypted(self) -> bool
            Returns if the session's connection is encrypted

        is_open(self) -> bool
            Returns if the session's connection is currently open

        is_session_user_from_domain(self) -> bool
            Return a boolean indicating whether or not the session's user is a member of the domain that we're
            communicating with, or is trusted from another domain.
            :returns: True if the user is from the domain we're communicating with, False otherwise.

        is_thread_safe(self) -> bool
            Returns if the session's connection is thread-safe

        object_exists_in_domain_with_attribute(self, attr: str, unescaped_value: str) -> bool
            Check if any objects exist in the domain with a given attribute. Returns True if so, False otherwise.
            :param attr: The LDAP attribute to examine in the search.
            :param unescaped_value: The value of the attribute that we're looking for, in its raw form.
            :returns: True if any objects exist in the domain with the attribute specified equal to the value.

        overwrite_attribute_for_computer(self, computer: Union[str, ms_active_directory.core.ad_objects.ADComputer], attribute: str, value, controls: List[ldap3.protocol.rfc4511.Control] = None, raise_exception_on_failure: bool = True, skip_validation: bool = False) -> bool
            Atomically overwrite the value of an attribute for a computer in the domain.

            :param computer: Either an ADComputer object or string name referencing the computer to be modified.
            :param attribute: A string specifying the name of the LDAP attribute to be overwritten.
            :param value: The value to set for the attribute. Value may either be a primitive, such as a string, bytes,
                          or a number, if a single value will be set. Value may also be an iterable such as a set or
                          a list if a multi-valued attribute will be set.
            :param controls: LDAP controls to use during the modification operation.
            :param raise_exception_on_failure: If true, an exception will be raised with additional details if the modify
                                               fails.
            :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                    Defaults to False. This can be used to make this function more performant when
                                    the caller knows all the distinguished names being specified are valid, as it
                                    performs far fewer queries.
            :returns: True if the operation succeeds, False otherwise.
            :raises: InvalidLdapParameterException if any attributes or values are malformed.
            :raises: ObjectNotFoundException if a distinguished name is specified and cannot be found
            :raises: AttributeModificationException if raise_exception_on_failure is True and we fail
            :raises: Other LDAP exceptions from the ldap3 library if the connection is configured to raise exceptions and
                     issues are seen such as determining that a value is malformed based on the server schema.

        overwrite_attribute_for_group(self, group: Union[str, ms_active_directory.core.ad_objects.ADGroup], attribute: str, value, controls: List[ldap3.protocol.rfc4511.Control] = None, raise_exception_on_failure: bool = True, skip_validation: bool = False) -> bool
            Atomically overwrite the value of an attribute for a group in the domain.

            :param group: Either an ADUser object or string name referencing the group to be modified.
            :param attribute: A string specifying the name of the LDAP attribute to be overwritten.
            :param value: The value to set for the attribute. Value may either be a primitive, such as a string, bytes,
                          or a number, if a single value will be set. Value may also be an iterable such as a set or
                          a list if a multi-valued attribute will be set.
            :param controls: LDAP controls to use during the modification operation.
            :param raise_exception_on_failure: If true, an exception will be raised with additional details if the modify
                                               fails.
            :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                    Defaults to False. This can be used to make this function more performant when
                                    the caller knows all the distinguished names being specified are valid, as it
                                    performs far fewer queries.
            :returns: True if the operation succeeds, False otherwise.
            :raises: InvalidLdapParameterException if any attributes or values are malformed.
            :raises: ObjectNotFoundException if a distinguished name is specified and cannot be found
            :raises: AttributeModificationException if raise_exception_on_failure is True and we fail
            :raises: Other LDAP exceptions from the ldap3 library if the connection is configured to raise exceptions and
                     issues are seen such as determining that a value is malformed based on the server schema.

        overwrite_attribute_for_object(self, ad_object: Union[str, ms_active_directory.core.ad_objects.ADObject], attribute: str, value, controls: List[ldap3.protocol.rfc4511.Control] = None, raise_exception_on_failure: bool = True, skip_validation: bool = False) -> bool
            Atomically overwrite the value of an attribute for an object in the domain.

            :param ad_object: Either an ADObject object or string distinguished name referencing the object to be modified.
            :param attribute: A string specifying the name of the LDAP attribute to be overwritten.
            :param value: The value to set for the attribute. Value may either be a primitive, such as a string, bytes,
                          or a number, if a single value will be set. Value may also be an iterable such as a set or
                          a list if a multi-valued attribute will be set.
            :param controls: LDAP controls to use during the modification operation.
            :param raise_exception_on_failure: If true, an exception will be raised with additional details if the modify
                                               fails.
            :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                    Defaults to False. This can be used to make this function more performant when
                                    the caller knows all the distinguished names being specified are valid, as it
                                    performs far fewer queries.
            :returns: True if the operation succeeds, False otherwise.
            :raises: InvalidLdapParameterException if any attributes or values are malformed.
            :raises: ObjectNotFoundException if a distinguished name is specified and cannot be found
            :raises: AttributeModificationException if raise_exception_on_failure is True and we fail
            :raises: Other LDAP exceptions from the ldap3 library if the connection is configured to raise exceptions and
                     issues are seen such as determining that a value is malformed based on the server schema.

        overwrite_attribute_for_user(self, user: Union[str, ms_active_directory.core.ad_objects.ADUser], attribute: str, value, controls: List[ldap3.protocol.rfc4511.Control] = None, raise_exception_on_failure: bool = True, skip_validation: bool = False) -> bool
            Atomically overwrite the value of an attribute for a user in the domain.

            :param user: Either an ADUser object or string name referencing the user to be modified.
            :param attribute: A string specifying the name of the LDAP attribute to be overwritten.
            :param value: The value to set for the attribute. Value may either be a primitive, such as a string, bytes,
                          or a number, if a single value will be set. Value may also be an iterable such as a set or
                          a list if a multi-valued attribute will be set.
            :param controls: LDAP controls to use during the modification operation.
            :param raise_exception_on_failure: If true, an exception will be raised with additional details if the modify
                                               fails.
            :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                    Defaults to False. This can be used to make this function more performant when
                                    the caller knows all the distinguished names being specified are valid, as it
                                    performs far fewer queries.
            :returns: True if the operation succeeds, False otherwise.
            :raises: InvalidLdapParameterException if any attributes or values are malformed.
            :raises: ObjectNotFoundException if a distinguished name is specified and cannot be found
            :raises: AttributeModificationException if raise_exception_on_failure is True and we fail
            :raises: Other LDAP exceptions from the ldap3 library if the connection is configured to raise exceptions and
                     issues are seen such as determining that a value is malformed based on the server schema.

        overwrite_attributes_for_computer(self, computer: Union[str, ms_active_directory.core.ad_objects.ADComputer], attribute_to_value_map: dict, controls: List[ldap3.protocol.rfc4511.Control] = None, raise_exception_on_failure: bool = True, skip_validation: bool = False) -> bool
            Atomically overwrite values of multiple attributes for a computer in the domain.

            :param computer: Either an ADComputer object or string name referencing the computer to have attributes
                             overwritten.
            :param attribute_to_value_map: A dictionary mapping string LDAP attribute names to values that will be used
                                           in the modification operation. Values may either be primitives, such as strings,
                                           bytes, and numbers if a single value will set. Values may also be iterables
                                           such as sets and lists if an attribute is multi-valued and multiple values will
                                           be set.
            :param controls: LDAP controls to use during the modification operation.
            :param raise_exception_on_failure: If true, an exception will be raised with additional details if the modify
                                               fails.
            :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                    Defaults to False. This can be used to make this function more performant when
                                    the caller knows all the distinguished names being specified are valid, as it
                                    performs far fewer queries.
            :returns: True if the operation succeeds, False otherwise.
            :raises: InvalidLdapParameterException if any attributes or values are malformed.
            :raises: ObjectNotFoundException if a name is specified and cannot be found
            :raises: AttributeModificationException if raise_exception_on_failure is True and we fail
            :raises: Other LDAP exceptions from the ldap3 library if the connection is configured to raise exceptions and
                     issues are seen such as determining that a value is malformed based on the server schema.

        overwrite_attributes_for_group(self, group: Union[str, ms_active_directory.core.ad_objects.ADGroup], attribute_to_value_map: dict, controls: List[ldap3.protocol.rfc4511.Control] = None, raise_exception_on_failure: bool = True, skip_validation: bool = False) -> bool
            Atomically overwrite values of multiple attributes for a group in the domain.

            :param group: Either an ADGroup object or string name referencing the group to have attributes overwritten.
            :param attribute_to_value_map: A dictionary mapping string LDAP attribute names to values that will be used
                                           in the modification operation. Values may either be primitives, such as strings,
                                           bytes, and numbers if a single value will set. Values may also be iterables
                                           such as sets and lists if an attribute is multi-valued and multiple values will
                                           be set.
            :param controls: LDAP controls to use during the modification operation.
            :param raise_exception_on_failure: If true, an exception will be raised with additional details if the modify
                                               fails.
            :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                    Defaults to False. This can be used to make this function more performant when
                                    the caller knows all the distinguished names being specified are valid, as it
                                    performs far fewer queries.
            :returns: True if the operation succeeds, False otherwise.
            :raises: InvalidLdapParameterException if any attributes or values are malformed.
            :raises: ObjectNotFoundException if a name is specified and cannot be found
            :raises: AttributeModificationException if raise_exception_on_failure is True and we fail
            :raises: Other LDAP exceptions from the ldap3 library if the connection is configured to raise exceptions and
                     issues are seen such as determining that a value is malformed based on the server schema.

        overwrite_attributes_for_object(self, ad_object: Union[str, ms_active_directory.core.ad_objects.ADObject], attribute_to_value_map: dict, controls: List[ldap3.protocol.rfc4511.Control] = None, raise_exception_on_failure: bool = True, skip_validation: bool = False) -> bool
            Atomically overwrite values of multiple attributes for an object in the domain.

            :param ad_object: Either an ADObject object or string distinguished name referencing the object to be modified.
            :param attribute_to_value_map: A dictionary mapping string LDAP attribute names to values that will be used
                                           in the modification operation. Values may either be primitives, such as strings,
                                           bytes, and numbers if a single value will set. Values may also be iterables
                                           such as sets and lists if an attribute is multi-valued and multiple values will
                                           be set.
            :param controls: LDAP controls to use during the modification operation.
            :param raise_exception_on_failure: If true, an exception will be raised with additional details if the modify
                                               fails.
            :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                    Defaults to False. This can be used to make this function more performant when
                                    the caller knows all the distinguished names being specified are valid, as it
                                    performs far fewer queries.
            :returns: True if the operation succeeds, False otherwise.
            :raises: InvalidLdapParameterException if any attributes or values are malformed.
            :raises: ObjectNotFoundException if a distinguished name is specified and cannot be found
            :raises: AttributeModificationException if raise_exception_on_failure is True and we fail
            :raises: Other LDAP exceptions from the ldap3 library if the connection is configured to raise exceptions and
                     issues are seen such as determining that a value is malformed based on the server schema.

        overwrite_attributes_for_user(self, user: Union[str, ms_active_directory.core.ad_objects.ADUser], attribute_to_value_map: dict, controls: List[ldap3.protocol.rfc4511.Control] = None, raise_exception_on_failure: bool = True, skip_validation: bool = False) -> bool
            Atomically overwrite values of multiple attributes for a user in the domain.

            :param user: Either an ADUser object or string name referencing the user to have attributes overwritten.
            :param attribute_to_value_map: A dictionary mapping string LDAP attribute names to values that will be used
                                           in the modification operation. Values may either be primitives, such as strings,
                                           bytes, and numbers if a single value will set. Values may also be iterables
                                           such as sets and lists if an attribute is multi-valued and multiple values will
                                           be set.
            :param controls: LDAP controls to use during the modification operation.
            :param raise_exception_on_failure: If true, an exception will be raised with additional details if the modify
                                               fails.
            :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                    Defaults to False. This can be used to make this function more performant when
                                    the caller knows all the distinguished names being specified are valid, as it
                                    performs far fewer queries.
            :returns: True if the operation succeeds, False otherwise.
            :raises: InvalidLdapParameterException if any attributes or values are malformed.
            :raises: ObjectNotFoundException if a name is specified and cannot be found
            :raises: AttributeModificationException if raise_exception_on_failure is True and we fail
            :raises: Other LDAP exceptions from the ldap3 library if the connection is configured to raise exceptions and
                     issues are seen such as determining that a value is malformed based on the server schema.

        remove_computers_from_groups(self, computers_to_remove: List[Union[str, ms_active_directory.core.ad_objects.ADComputer]], groups_to_remove_them_from: List[Union[str, ms_active_directory.core.ad_objects.ADGroup]], stop_and_rollback_on_error: bool = True, controls: List[ldap3.protocol.rfc4511.Control] = None, skip_validation: bool = False) -> List[Union[str, ms_active_directory.core.ad_objects.ADGroup]]
            Remove one or more computers from one or more groups as members. This function attempts to be idempotent
            and will not remove computers that are not already members.

            :param computers_to_remove: A list of computers to remove from groups. These may either be ADComputer objects or
                                        string name identifiers for computers.
            :param groups_to_remove_them_from: A list of groups to remove members from. These may either be ADGroup objects
                                               or string name identifiers for groups.
            :param stop_and_rollback_on_error: If true, failure to remove any of the computers from any of the groups
                                               will cause us to try and add any computers that have been removed back to any
                                               of the groups that we successfully removed members from.
            :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                             whether or not certain properties/attributes are critical, which influences whether a search
                             may succeed or fail based on their availability.
            :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                    Defaults to False. This can be used to make this function more performant when
                                    the caller knows all the distinguished names being specified are valid, as it
                                    performs far fewer queries.
            :returns: A list of groups that successfully had members removed. This will always be all the groups unless
                      stop_and_rollback_on_error is False.
            :raises: MembershipModificationException if we fail to remove computers from any groups and rollback succeeds
            :raises: MembershipModificationRollbackException if we fail to remove any computers from groups, and then
                     also fail when adding the computers that had been removed successfully, leaving us in a partially
                     completed state. This may occur if the session has permission to remove members but not to add members.

        remove_groups_from_groups(self, groups_to_remove: List[Union[str, ms_active_directory.core.ad_objects.ADGroup]], groups_to_remove_them_from: List[Union[str, ms_active_directory.core.ad_objects.ADGroup]], stop_and_rollback_on_error: bool = True, controls: List[ldap3.protocol.rfc4511.Control] = None, skip_validation: bool = False) -> List[Union[str, ms_active_directory.core.ad_objects.ADGroup]]
            Remove one or more groups from one or more groups as members. This function attempts to be idempotent
            and will not remove groups that are not already members.

            :param groups_to_remove: A list of groups to remove from other groups. These may either be ADGroup objects or
                                     string name identifiers for groups.
            :param groups_to_remove_them_from: A list of groups to remove members from. These may either be ADGroup objects
                                               or string name identifiers for groups.
            :param stop_and_rollback_on_error: If true, failure to remove any of the groups from any of the other groups
                                               will cause us to try and add any groups that have been removed back to any
                                               of the groups that we successfully removed members from.
            :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                             whether or not certain properties/attributes are critical, which influences whether a search
                             may succeed or fail based on their availability.
            :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                    Defaults to False. This can be used to make this function more performant when
                                    the caller knows all the distinguished names being specified are valid, as it
                                    performs far fewer queries.
            :returns: A list of groups that successfully had members removed. This will always be all the groups unless
                      stop_and_rollback_on_error is False.
            :raises: MembershipModificationException if we fail to remove groups from any other groups and rollback succeeds
            :raises: MembershipModificationRollbackException if we fail to remove any groups from other groups, and then
                     also fail when adding the groups that had been removed successfully, leaving us in a partially
                     completed state. This may occur if the session has permission to remove members but not to add members.

        remove_users_from_groups(self, users_to_remove: List[Union[str, ms_active_directory.core.ad_objects.ADUser]], groups_to_remove_them_from: List[Union[str, ms_active_directory.core.ad_objects.ADGroup]], stop_and_rollback_on_error: bool = True, controls: List[ldap3.protocol.rfc4511.Control] = None, skip_validation: bool = False) -> List[Union[str, ms_active_directory.core.ad_objects.ADGroup]]
            Remove one or more users from one or more groups as members. This function attempts to be idempotent
            and will not remove users that are not already members.

            :param users_to_remove: A list of users to remove from groups. These may either be ADUsers objects or
                                    string name identifiers for users.
            :param groups_to_remove_them_from: A list of groups to remove members from. These may either be ADGroup objects
                                               or string name identifiers for groups.
            :param stop_and_rollback_on_error: If true, failure to remove any of the users from any of the groups
                                               will cause us to try and add any users that have been removed back to any
                                               of the groups that we successfully removed members from.
            :param controls: A list of LDAP controls to use when performing the search. These can be used to specify
                             whether or not certain properties/attributes are critical, which influences whether a search
                             may succeed or fail based on their availability.
            :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                    Defaults to False. This can be used to make this function more performant when
                                    the caller knows all the distinguished names being specified are valid, as it
                                    performs far fewer queries.
            :returns: A list of groups that successfully had members removed. This will always be all the groups unless
                      stop_and_rollback_on_error is False.
            :raises: MembershipModificationException if we fail to remove users from any groups and rollback succeeds
            :raises: MembershipModificationRollbackException if we fail to remove any users from groups, and then
                     also fail when adding the users that had been removed successfully, leaving us in a partially
                     completed state. This may occur if the session has permission to remove members but not to add members.

        reset_password_for_account(self, account: Union[str, ms_active_directory.core.ad_objects.ADUser, ms_active_directory.core.ad_objects.ADComputer], new_password: str, skip_validation: bool = False) -> bool
            Resets a password for a user (includes computers) to a new desired password.
            To reset a password, a new password is provided to replace the current one without providing the current
            password. This is a privileged operation and maps to the RESET_PASSWORD permission in AD.

            :param account: The account whose password is being changed. This may either be a string account name, to be
                            looked up, or an ADObject object.
            :param new_password: The new password for the account.
            :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                    Defaults to False. This can be used to make this function more performant when
                                    the caller knows all the distinguished names being specified are valid, as it
                                    performs far fewer queries.
            :returns: True if the operation succeeds. If the operation fails, either an exception will be raised or False
                      will be returned depending on whether the ldap connection for this session has "raise_exceptions"
                      set to True or not.

        set_computer_security_descriptor(self, computer: Union[str, ms_active_directory.core.ad_objects.ADComputer], new_sec_descriptor: ms_active_directory.environment.security.security_descriptor_utils.SelfRelativeSecurityDescriptor, raise_exception_on_failure: bool = True, skip_validation: bool = False) -> bool
            Set the security descriptor on an Active Directory computer. This can be used to change the owner of a
            computer in AD, change its permission ACEs, etc.

            :param computer: Either an ADComputer object or string name referencing the computer to be modified.
            :param new_sec_descriptor: The security descriptor to set on the object.
            :param raise_exception_on_failure: If true, raise an exception when modifying the object fails instead of
                                               returning False.
            :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                    Defaults to False. This can be used to make this function more performant when
                                    the caller knows all the distinguished names being specified are valid, as it
                                    performs far fewer queries.
            :returns: A boolean indicating success.
            :raises: InvalidLdapParameterException if computer is not a string or ADComputer object
            :raises: ObjectNotFoundException if a string DN is specified and it cannot be found
            :raises: PermissionDeniedException if we fail to modify the Security Descriptor and raise_exception_on_failure
                     is true

        set_domain_search_base(self, search_base: str)
            Set the search base to use for 'find' queries within the domain made by this session.
            This can be used to confine our search to a sub-container within the domain. This can improve
            the performance of lookups, avoid permissioning issues, and remove issues around duplicate
            records with the same common name.

        set_group_security_descriptor(self, group: Union[str, ms_active_directory.core.ad_objects.ADGroup], new_sec_descriptor: ms_active_directory.environment.security.security_descriptor_utils.SelfRelativeSecurityDescriptor, raise_exception_on_failure: bool = True, skip_validation: bool = False) -> bool
            Set the security descriptor on an Active Directory group. This can be used to change the owner of an
            group in AD, change its permission ACEs, etc.

            :param group: Either an ADGroup object or string name referencing the group to be modified
            :param new_sec_descriptor: The security descriptor to set on the object.
            :param raise_exception_on_failure: If true, raise an exception when modifying the object fails instead of
                                               returning False.
            :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                    Defaults to False. This can be used to make this function more performant when
                                    the caller knows all the distinguished names being specified are valid, as it
                                    performs far fewer queries.
            :returns: A boolean indicating success.
            :raises: ObjectNotFoundException if a string DN is specified and it cannot be found
            :raises: PermissionDeniedException if we fail to modify the Security Descriptor and raise_exception_on_failure
                     is true

        set_object_security_descriptor(self, ad_object: Union[str, ms_active_directory.core.ad_objects.ADObject], new_sec_descriptor: ms_active_directory.environment.security.security_descriptor_utils.SelfRelativeSecurityDescriptor, raise_exception_on_failure: bool = True, skip_validation: bool = False) -> bool
            Set the security descriptor on an Active Directory object. This can be used to change the owner of an
            object in AD, change its permission ACEs, etc.

            :param ad_object: Either an ADObject object or string distinguished name referencing the object to be modified
            :param new_sec_descriptor: The security descriptor to set on the object.
            :param raise_exception_on_failure: If true, raise an exception when modifying the object fails instead of
                                               returning False.
            :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                    Defaults to False. This can be used to make this function more performant when
                                    the caller knows all the distinguished names being specified are valid, as it
                                    performs far fewer queries.
            :returns: A boolean indicating success.
            :raises: ObjectNotFoundException if a string DN is specified and it cannot be found
            :raises: PermissionDeniedException if we fail to modify the Security Descriptor and raise_exception_on_failure
                     is true

        set_search_paging_size(self, new_size: int)

        set_trusted_domain_cache_lifetime_seconds(self, new_lifetime_in_seconds: int)

        set_user_security_descriptor(self, user: Union[str, ms_active_directory.core.ad_objects.ADUser], new_sec_descriptor: ms_active_directory.environment.security.security_descriptor_utils.SelfRelativeSecurityDescriptor, raise_exception_on_failure: bool = True, skip_validation: bool = False) -> bool
            Set the security descriptor on an Active Directory object. This can be used to change the owner of an
            user in AD, change its permission ACEs, etc.

            :param user: Either an ADUser object or string name referencing the user to be modified.
            :param new_sec_descriptor: The security descriptor to set on the object.
            :param raise_exception_on_failure: If true, raise an exception when modifying the object fails instead of
                                               returning False.
            :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                    Defaults to False. This can be used to make this function more performant when
                                    the caller knows all the distinguished names being specified are valid, as it
                                    performs far fewer queries.
            :returns: A boolean indicating success.
            :raises: InvalidLdapParameterException if user is not a string or ADUser object
            :raises: ObjectNotFoundException if a string DN is specified and it cannot be found
            :raises: PermissionDeniedException if we fail to modify the Security Descriptor and raise_exception_on_failure
                     is true

        take_over_existing_computer(self, computer: Union[ms_active_directory.core.managed_ad_objects.ManagedADComputer, ms_active_directory.core.ad_objects.ADObject, str], computer_password: str = None, old_computer_password: str = None) -> ms_active_directory.core.managed_ad_objects.ManagedADComputer
            Use the session to take over a computer in the domain and return a computer object.
            This resets the computer's password so that nobody else can impersonate it, and reads
            the computer's attributes in order to create a computer object and return it.
            :param computer: This can be an ManagedADComputer or ADObject object representing the computer that should be
                             taken over, or a string identifier for the computer.  If it is a string, it should be
                             the common name or sAMAccountName of the computer to find in the AD domain, or it can be
                             the distinguished name of a computer object.
                             If it appears to be a common name, not ending in $, a sAMAccountName will
                             be derived to search for. If that cannot be found, then a search will be
                             done for this as a common name. If no unique computer can be found with that
                             search, then an exception will be raised.
            :param computer_password: The password to be set for the computer. This is particularly
                                      useful to specify if the computer will be shared across multiple
                                      applications or devices, or if pre-creating a computer for another
                                      application to use. If not specified, a random 120 character
                                      password will be generated.
            :param old_computer_password: The current password for the computer. This is used to reduce the level of
                                          permissions needed for the takeover operation.
            :returns: an ManagedADComputer object representing the computer.
            :raises: DomainJoinException if any of our validation of the specified attributes fails or if anything
                     specified conflicts with objects in the domain.
            :raises: ObjectNotFoundException if a computer cannot be found based on the name specified.

        unlock_account(self, account: Union[str, ms_active_directory.core.ad_objects.ADComputer, ms_active_directory.core.ad_objects.ADUser], skip_validation: bool = False) -> bool
            Unlock a user who's been locked out for some period of time.
            :param account: The string name of the user/computer account that has been locked out. This may either be a
                            sAMAccountName, a distinguished name, or a unique common name. This can also be an ADObject,
                            and the distinguished name will be extracted from it.
            :param skip_validation: If true, assume all distinguished names exist and do not look them up.
                                    Defaults to False. This can be used to make this function more performant when
                                    the caller knows all the distinguished names being specified are valid, as it
                                    performs far fewer queries.
            :returns: True if the operation succeeds. If the operation fails, either an exception will be raised or False
                      will be returned depending on whether the ldap connection for this session has "raise_exceptions"
                      set to True or not.

        who_am_i(self) -> str
            Return the authorization identity of the session's user as recognized by the server.
            This can be helpful when a script is provided with an identity in one form that is used to start a session
            (e.g. a distinguished name, or a pre-populated kerberos cache) and then it wants to determine its identity
            that the server actually sees.
            This just calls the LDAP connection function, as it's suitable for AD as well.
            :returns: A string indicating the authorization identity of the session's user as recognized by the server.
    
