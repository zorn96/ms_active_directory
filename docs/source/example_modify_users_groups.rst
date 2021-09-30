Updating user, computer, or group attributes.
################################################

You can use this library to modify the values of various LDAP attributes on
users, computers, groups, or generic objects.

Users, computers, and groups provide the convenient name lookup functionality mentioned above,
while for generic objects you either need to pass an ``ADObject`` or a distinguished name.

Appending to one or more attributes
----------------------------------------
You can atomically append values to multi-valued attributes, such as ``accountNameHistory``.
This allows you to update their values without needing to know the current value or worry
about race conditions, as it's handled server-side.
::

    from ms_active_directory import ADDomain
    domain = ADDomain('example.com')
    session = domain.create_session_as_user('username@example.com', 'password')

    user_name = 'sarah1'
    previous_account_name = 'sarah'
    success = session.atomic_append_to_attribute_for_user(user_name, 'accountNameHistory',
                                                          previous_account_name)

    # you can also append multiple values at once, or append to multiple
    # attributes at once
    user_name = 'monica pham-chen'
    previous_account_names = ['monica pham', 'monica chen']
    previous_uid = 'mpham'
    update_map = {
        'accountNameHistory': previous_account_names,
        'uid': previous_uid
    }
    success = session.atomic_append_to_attributes_for_user(user_name, update_map)

You can also perform these actions on groups and objects using the similarly named
functions ``atomic_append_to_attribute_for_group``, ``atomic_append_to_attributes_for_group``,
``atomic_append_to_attribute_for_computer``, ``atomic_append_to_attributes_for_computer``,
``atomic_append_to_attribute_for_object``, and ``atomic_append_to_attributes_for_object``.

Overwriting one or more attributes
-----------------------------------
If you want to totally replace the value of an attribute, that's supported as well.
This can be done for single-valued or multi-valued attributes.

::

    from ms_active_directory import ADDomain
    domain = ADDomain('example.com')
    session = domain.create_session_as_user('username@example.com', 'password')

    user_name = 'arjun'
    new_uid_number = 1093
    success = session.overwrite_attribute_for_user(user_name, 'uidNumber',
                                                   new_uid_number)

    # just like appending, we can do multiple attributes at once atomically
    user_name = 'nikita'
    new_employee_type = 'Director'
    new_gid = 0
    new_addresses = [
       '123 mulberry lane',
       '456 vacation home drive'
    ]
    new_value_map = {
       'employeeType': new_employee_type,
       'gidNumber': new_gid,
       'postalAddress': new_addresses
    }
    success = session.overwrite_attributes_for_user(user_name, new_value_map)

You can also perform these actions on groups and objects using the similarly named
functions, just like with appending.
