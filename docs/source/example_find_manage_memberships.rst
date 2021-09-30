Managing User, Computer, and Group Membership
#############################################

You can look up the groups that a user belongs to, the groups that a computer belongs to,
or the groups that a group belongs to. Active Directory supports nested groups, which is why
there's ``user->groups``, ``computer->groups``, and ``group->groups`` mapping capability.

When querying the membership information for users or groups, the input type for any
user or group must either be a string name identifying the user, computer, or group as described in the prior
section, or must be an ``ADUser``, ``ADComputer``, or ``ADGroup`` object returned by one of the functions described
in the prior section.

Similarly to looking up users, computers, and groups, you can query for attributes of the parent groups
by providing a list of LDAP attributes to look up for them.

::

    from ms_active_directory import ADDomain
    domain = ADDomain('example.com')
    session = domain.create_session_as_user('username@example.com', 'password')

    user_sam_account_name = 'user-sam-1'
    user_dn = 'CN=user sam 1,CN=users,DC=example,DC=com'
    user_cn = 'user same 1'

    desired_group_attrs = ['gidNumber', 'managedBy']
    # all 3 of these do the same thing, and internally map the different
    # name types to a user object
    groups_res1 = session.find_groups_for_user(user_sam_account_name, desired_group_attrs)
    groups_res2 = session.find_groups_for_user(user_dn, desired_group_attrs)
    groups_res3 = session.find_groups_for_user(user_cn, desired_group_attrs)

    # you can also directly use a user object to query groups
    user_obj = session.find_user_by_name(user_sam_account_name)
    groups_res4 = session.find_groups_for_user(user_obj, desired_group_attrs)

    # you can also look up the parents of groups in the same way
    example_group_obj = groups_res4[0]
    example_group_dn = example_group_obj.distinguished_name

    # these both work. sAMAccountName could also be used, etc.
    second_level_groups_res1 = session.find_groups_for_group(example_group_obj, desired_group_attrs)
    second_level_groups_res2 = session.find_groups_for_group(example_group_dn, desired_group_attrs)


You can also query ``users->groups``, ``computers->groups``, and ``groups->groups`` to find the memberships of multiple
users, computers, and groups, and the library will make a minimal number of queries to determine membership;
it will be more efficient that doing a ``user->groups`` for each user (or similar for computers and groups).
The result will be a map that maps the input users or groups to lists of parent groups.

The input lists' elements must be the same format as what's provided when looking up group
memberships for a single user or group.
::

    from ms_active_directory import ADDomain
    domain = ADDomain('example.com')
    session = domain.create_session_as_user('username@example.com', 'password')

    user1_name = 'user1'
    user2_name = 'user2'
    users = [user1_name, user2_name]
    desired_group_attrs = ['gidNumber', 'managedBy']

    user_group_map = session.find_groups_for_users(users, desired_group_attrs)
    # the dictionary result keys are the users from the input
    user1_groups = user_group_map[user1_name]
    user2_groups = user_group_map[user2_name]

    # you can use the groups->groups mapping functionality to enumerate the
    # full tree of a users' group memberships (or a groups' group memberships)
    user1_second_level_groups_map = session.find_groups_for_groups(user1_groups, desired_group_attrs)
    all_second_level_groups = []
    for group_list in user1_second_level_groups_map.values():
        for group in group_list:
            if group not in all_second_level_groups:
                all_second_level_groups.append(group)
    all_user1_groups_in_2_levels = user1_groups + all_second_level_groups


Finding the members of groups
-----------------------------
You can look up the members of one or more groups and get attributes about those
members.
::

    from ms_active_directory import ADDomain, ADUser, ADGroup
    domain = ADDomain('example.com')
    session = domain.create_session_as_user('username@example.com', 'password')

    # get emails of users and groups that are members
    desired_attrs = ['mail']

    # look up members of a single group
    single_group_member_list = session.find_members_of_group('group1', desired_attrs)

    # look up members of multiple groups at once
    groups = ['group1', 'group2']
    group_to_member_list_map = session.find_members_of_groups(groups, desired_attrs)
    group2_member_list = group_to_member_list_map['group2']
    group2_user_members = [mem for mem in group2_member_list if isintance(mem, ADUser)]
    group2_group_members = [mem for mem in group2_member_list if isintance(mem, ADGroup)]


You can also look up members recursively to handle nesting.
A maximum depth for lookups may be specified, but by default all
nesting will be enumerated.
::

    from ms_active_directory import ADDomain, ADUser, ADGroup
    domain = ADDomain('example.com')
    session = domain.create_session_as_user('username@example.com', 'password')

    # get emails of users and groups that are members
    desired_attrs = ['mail']
    group_name = 'has-groups-as-members'
    groups_to_member_lists_maps = session.find_members_of_groups_recursive(group_name, desired_attrs)



Adding users to groups
-----------------------
You can add users to groups by specifying a list of ``ADUser`` objects or string names of
AD users to be added to the groups, and a list of ``ADGroup`` objects or string names of AD
groups to add the users to.

If string names are specified, they'll be mapped to users/groups using the functions
discussed in the prior sections.

If a user is already in a group, this is idempotent and will not re-add them.

::

    from ms_active_directory import ADDomain
    domain = ADDomain('example.com')
    session = domain.create_session_as_user('username@example.com', 'password')

    user1_name = 'user1'
    user2_name = 'user2'
    group1_name = 'target-group1'
    group2_name = 'target-group2'

    session.add_users_to_groups([user1_name, user2_name],
                                [group1_name, group2_name])


By default, if we fail to add users to one of the groups specified, we'll attempt to rollback
and remove users from any groups they were added to. You can choose to forgo this and a list of
groups that users were successfully added to will be returned instead.
::

    from ms_active_directory import ADDomain
    domain = ADDomain('example.com')
    session = domain.create_session_as_user('username@example.com', 'password')

    user1_name = 'user1'
    user2_name = 'user2'
    group1_name = 'target-group1'
    group2_name = 'target-group2'
    privileged_group = 'group-that-will-fail'

    succeeeded = session.add_users_to_groups([user1_name, user2_name],
                                             [group1_name, group2_name, privileged_group],
                                             stop_and_rollback_on_error=False)
    # this will print "['target-group1', 'target-group2']" assuming that
    # adding users to 'group-that-will-fail' failed
    print(succeeeded)


Adding groups to groups
-----------------------

Adding groups to other groups works exactly the same way as adding users to groups, but
the function is called ``add_groups_to_groups`` and both inputs are lists of groups.

Adding computers to groups
--------------------------

Adding computers to groups works exactly the same way as adding users to groups, but
the function is called ``add_computers_to_groups`` and the first input is a list of computers.

Removing users, computers, or groups from groups
---------------------------------------------------
Removing users, computers, or groups from groups works identically to adding users, computers, or groups to groups,
including input format, idempotency, and rollback functionality.
The only difference is that the functions are called ``remove_users_from_groups``, ``remove_computers_from_groups``, and
``remove_groups_from_groups`` instead.
