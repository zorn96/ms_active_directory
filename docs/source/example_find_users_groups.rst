Finding users, computers, and groups
###########################################

The library provides a number of different functions for finding users, computers, and groups by different
identifiers, and for querying information about them.

Looking up users, computers, groups, and information about them
------------------------------------------------------------------
Users, computers, and groups can both be looked up by one of:

- sAMAccountName
- distinguished name
- common name
- a generic "name" that will attempt the above 3
- an attribute

Look up by sAMAccountName
-------------------------

A ``sAMAccountName`` is unique within a domain, and so looking up users or
groups by ``sAMAccountName`` returns a single result.
``sAMAccountName`` was a user's windows logon name in older versions of windows,
and may be referred to as such in some documentation.

For computers, the standard convention is for their ``sAMAccountName`` to end with
a ``$``, but many tools/docs leave that out. So if a ``sAMAccountName`` is specified
that does not end with a ``$`` and cannot be found, a lookup will also be
attempted after adding a ``$`` to the end.

When looking up users, computers, and groups, you can also query for additional information
about them by specifying a list of LDAP attributes.
::

    from ms_active_directory import ADDomain
    domain = ADDomain('example.com')
    session = domain.create_session_as_user('username@example.com', 'password')

    user = session.find_user_by_sam_name('user1', ['employeeID'])
    group = session.find_group_by_sam_name('group1', ['gidNumber'])
    # users and groups support a generic "get" for any attributes queried
    print(user.get('employeeID'))
    print(group.get('gidNumber'))


Look up by distinguished name
-----------------------------

A distinguished name is unique within a forest, and so looking up users or
groups by it returns a single result.
A distinguished name should not be escaped when provided to the search function.

When looking up users, computers, and groups, you can also query for additional information
about them by specifying a list of LDAP attributes.
::

    from ms_active_directory import ADDomain
    domain = ADDomain('example.com')
    session = domain.create_session_as_user('username@example.com', 'password')

    user_dn = 'CN=user one,CN=Users,DC=example,DC=com'
    user = session.find_user_by_distinguished_name(user_dn, ['employeeID'])
    group_dn = 'CN=group one,OU=employee-groups,DC=example,DC=com'
    group = session.find_group_by_distinguished_name(group_dn, ['gidNumber'])
    # users and groups support a generic "get" for any attributes queried
    print(user.get('employeeID'))
    print(group.get('gidNumber'))


Look up by common name
----------------------
A common name is not unique within a domain, and so looking up users or
groups by it returns a list of results, which may have 0 or more entries.

When looking up users, computers, and groups, you can also query for additional information
about them by specifying a list of LDAP attributes.
::

    from ms_active_directory import ADDomain
    domain = ADDomain('example.com')
    session = domain.create_session_as_user('username@example.com', 'password')

    user_cn = 'John Doe'
    users = session.find_users_by_common_name(user_cn, ['employeeID'])
    group_dn = 'operations managers'
    groups = session.find_groups_by_common_name(group_dn, ['gidNumber'])
    # users and groups support a generic "get" for any attributes queried
    for user in users:
        print(user.get('employeeID'))
    for group in groups:
        print(group.get('gidNumber'))


Look up by generic name
-----------------------
You can also query by a generic "name", and the library will attempt to find a
unique user or group with that name. The library will either lookup by DN or will
attempt ``sAMAccountName`` and common name lookups depending on the name format.

If more than one result is found by common name and no result is found by
``sAMAccountName`` then this will produce an error.
::

    from ms_active_directory import ADDomain
    domain = ADDomain('example.com')
    session = domain.create_session_as_user('username@example.com', 'password')

    user_name = 'John Doe'
    user = session.find_user_by_name(user_name, ['employeeID'])
    group_name = 'operations managers'
    groups = session.find_groups_by_name(group_name, ['gidNumber'])
    # users and groups support a generic "get" for any attributes queried
    print(user.get('employeeID'))
    print(group.get('gidNumber'))


Look up by attribute
----------------------
You can also query for users, computers, or groups that possess a certain value for a
specified attribute. This can produce any number of results, so a list is
returned.
::

    from ms_active_directory import ADDomain
    domain = ADDomain('example.com')
    session = domain.create_session_as_user('username@example.com', 'password')

    desired_employee_type = 'temporary'
    users = session.find_users_by_attribute('employeeType', desired_employee_type, ['employeeID'])
    desired_group_manager = 'Alice P Hacker'
    groups = session.find_groups_by_attribute('managedBy', desired_group_manager, ['gidNumber'])

    # users and groups support a generic "get" for any attributes queried
    for user in users:
        print(user.distinguished_name)
        print(user.get('employeeID'))
    for group in groups:
        print(group.distinguished_name)
        print(group.get('gidNumber'))
