# ms_active_directory - A Library for Integrating with Microsoft Active Directory
This is a library for integrating with Microsoft Active Directory domains.

It supports a variety of common, critical functionality for integration of computers
into a domain, including the ability to discover domain resources, optimize
communication for speed, join a computer to the domain, and look up information
about users and groups in the domain.

It primarily builds on the LDAP protocol, and supports LDAP over TLS with channel bindings,
and all LDAP basic, NTLM, and SASL authentication mechanisms (e.g. Kerberos) supported by the
`ldap3` python library.

For more detailed documentation, please see the docs at:\
**https://ms-active-directory.readthedocs.io/**

**Author**: Azaria Zornberg
\
**Email**: a.zornberg96@gmail.com

# Key Features
1. Joining a computer to a domain, either by creating a new computer account or taking over an existing
   account.
2. Discovering domain resources and properties, optimizing domain communication for the network
3. Discovering trusted domains, including MIT Kerberos domains and trusted Active Directory domains, and their
   attributes (e.g. are the trusts transitive? is SID filtering used? what direction is the trust?)
4. Transferring authenticated sessions from one domain to its trusted domains, allowing for easy querying
   capability across domains for widely trusted users. This can be used to trace foreign security principals
   across domains without needing to spin up and manage new domain objects for each.
5. Finding users, computers, and groups based on a variety of properties (e.g. name, SID, user-specified properties)
6. Querying information about users, computers, groups, and generic objects
7. Looking up user, computer, and group memberships
8. Looking up members of groups, regardless of type, and their attributes. This can also be done with auto-recursion
   for nested groups.
9. Adding and removing users, computers, and groups to and from other groups
10. Account management functionality for both users and computers, such as password changes/resets, enabling, disabling, and unlocking accounts
12. Looking up information about the permissions set on a user, computer, group, or generic object
13. Adding permissions to the security descriptor for a user, computer, group, or generic object
14. Support for updating attributes of users, computers, groups, and generic objects. Support exists for atomically appending 
    or overwriting values.
15. Support for finding policies within a domain, and for finding the policies directly attached to any given object.


# Examples

## Discovering a domain

The library supports discovering LDAP and Kerberos servers within a domain using special DNS
entries defined for Active Directory.

### Smart Defaults
By default, it will use the system DNS configuration, find LDAP servers that support TLS, and sort
LDAP and Kerberos servers by the RTT to communicate with them.
```
from ms_active_directory import ADDomain

example_domain_dns_name = 'example.com'
domain = ADDomain(example_domain_dns_name)
ldap_servers = domain.get_ldap_uris()
kerberos_servers = domain.get_kerberos_uris()

# re-discover servers in dns and sort them by RTT again at a later time to pick up changes
domain.refresh_ldap_server_discovery()
domain.refresh_kerberos_server_discovery()
```


### Site Awareness and Flexible DNS
The library also supports site awareness, which will result in only discovering servers within a specified
Active Directory Site. You can also specify alternative DNS nameservers to use instead of the system ones.
```
from ms_active_directory import ADDomain

example_domain_dns_name = 'example.com'
site_name = 'us-eastern-datacenter'
domain = ADDomain(example_domain_dns_name, site=site_name,
                  dns_nameservers=['eastern-private-dns-01.local'])
```

### Network Multi-Tenancy and Security Support
You can also specify exactly which LDAP or Kerberos servers should be used, and skip discovery.
Additional configurations are available such as configuring the CA file path to use for
trust, and the source IP to use for outbound traffic to the domain, which is helpful when
there are firewall rules in place, or when a machine has both private and public IP addresses.
```
from ms_active_directory import ADDomain

example_domain_dns_name = 'example.com'
local_machine_ip = '10.251.12.1'
local_ldap_ip = '10.251.12.30'
public_machine_ip = '194.32.21.30'
# the servers that live on the public internet use well-known public
# CAs for trust, but we have a local CA for the private network servers
private_securing_cas = '/etc/internal-ca.cert'

# set up an object for the local domain in the same network as this machine,
# but also have an instance that can be used to make instances to reach out
# to the rest of the domain outside of the local private network
local_domain = ADDomain(example_domain_dns_name, ldap_servers_or_uris=[local_ldap_ip],
                        source_ip=local_ldap_ip, ca_certificates_file_path=private_securing_cas)
global_domain = ADDomain(example_domain_dns_name, source_ip=public_machine_ip)
```

## Establishing a session with a domain

You can establish a session with the AD Domain on behalf of either a user or computer.

Broadly, any keyword arguments that would normally be supported when creating a `Connection`
with the `ldap3` library are supported when creating a session, allowing
for flexibility while still providing an "it just works" option for
most users.

### Support for Computer Authentication
Computers default to using Kerberos SASL authentication, as SIMPLE authentication is
not support for computers with Active Directory.
To use kerberos, either `gssapi` or `winkerberos` must be
installed.
```
from ms_active_directory import ADDomain
domain = ADDomain('example.com')

# when using kerberos auth, the default is to use the kerberos
# credential cache on the machine, so no password is needed
computer_name = 'machine01'
session1 = domain.create_session_as_computer(computer_name)

# but you can pass sasl credentials, and if you use gssapi you can
# specify a username and password
# see the ldap3 documentation for details on SASL credentials and other
# connection options
other_name = 'other-machine-identity'
password = 'password01'
session2 = domain.create_session_as_computer(other_name, sasl_credentials=('', other_name, password))
```

You can also use other authentication mechanisms like NTLM.
``` 
from ldap3 import NTLM
from ms_active_directory import ADDomain
domain = ADDomain('example.com')

ntlm_name = 'EXAMPLE.COM\\computer01'
password = 'password1'
session = domain.create_session_as_computer(ntlm_name, password, authentication_mechanism=NTLM)
```

### Support for User Authentication

You can authenticate as a user by using simple binds, or by using SASL
mechanisms or NTLM as computers do.
The default for users is simple binds.
```
from ldap3 import NTLM
from ms_active_directory import ADDomain
domain = ADDomain('example.com')

session = domain.create_session_as_user('username@example.com', 'password')
ntlm_session =  domain.create_session_as_user('username@example.com', 'password',
                                              authentication_mechanism=NTLM)
```

## Discovering additional domain resources

The library supports discovering a wide variety of information about the domain beyond
the basics needed to communicate with it. This discovery doesn't require you to know any
niche information about Active Directory.

Discoverable resources include but are not limited to:
- Supported SASL mechanisms, which is important for authentication
- The current domain time, which is important for NTP synchronization
- Domain Functional Level, which governs things like support encryption types
- DNS servers
- Issuing certificates for CAs in the domain

### Finding supported SASL mechanisms
Discovering SASL mechanisms can be done without needing to create a session
with a domain, as it's needed before authentication in many cases.
```
from ms_active_directory import ADDomain
domain = ADDomain('example.com') 

# might print "['EXTERNAL', 'DIGEST-MD5']"
print(domain.find_supported_sasl_mechanisms())
```

### Finding the current domain time
Discovering the domain time can be done without needing to create a session
with a domain, as time synchronization is necessary for kerberos authentication
to succeed and can impact TLS negotiation as well.
```
from ms_active_directory import ADDomain
domain = ADDomain('example.com') 

# returns a python datetime object in utc time
curr_time = domain.find_current_time()

# allowed drift defaults to 5 minutes which is the kerberos standard,
# but we can use a shorter window to detect drift before it causes an
# outage. this returns a boolean
synced = domain.is_close_in_time_to_localhost(allowed_drift_seconds=60)
```

### Finding the domain functional level
Discovering the domain time can be done without needing to create a session
with a domain, as it can inform us as to what encryption types and TLS versions/ciphers
will be supported by the domain.
```
from ms_active_directory import ADDomain
domain = ADDomain('example.com') 

# find_functional_level returns an enum indicating the level.
# decision making based on level should be done based on the
# needs of your application
print(domain.find_functional_level())
```

### Finding DNS servers
Discovering DNS servers requires an authenticated session with the domain,
as searching the records within the domain for computers that run a DNS
service is privileged.
```
from ms_active_directory import ADDomain
domain = ADDomain('example.com')

session = domain.create_session_as_user('username@example.com', 'password')
# returns a map that maps server hostnames -> ip addresses, where
# the hostnames are computers running dns services
dns_map = session.find_dns_servers_for_domain()
ip_addrs = dns_map.values()
hostnames = dns_map.keys()
```

### Finding CA certificates
Discovering DNS servers requires an authenticated session with the domain,
as searching the records within the domain for records that are indicated
as being certificate authorities is privileged.

```
from ms_active_directory import ADDomain
domain = ADDomain('example.com')

session = domain.create_session_as_user('username@example.com', 'password')
# returns a list of PEM-formatted strings representing the signing certificates
# of all certificate authorities in the domain
pem_certs = session.find_certificate_authorities_for_domain()

# you can also get the certificates in DER format, which might be
# preferred on windows
der_certs = session.find_certificate_authorities_for_domain(pem_format=False)
```

## Joining an Active Directory domain

The action of joining a computer to a domain is not a well-defined operation,
and so the exact mechanics of how you utilize the domain joining functionality
and how its outputs are integrated with the rest of your system will vary depending on
your use case.

This will try to cover some common examples.

### Join the domain with default configurations for everything
The default behavior requires only the domain name and the credentials of a user with
sufficient administrative rights to create computers within the domain.
```
from ms_active_directory import join_ad_domain

comp = join_ad_domain('example.com', 'Administrator@example.com', 'example-password')
```
The `join_ad_domain` function returns a `ManagedADComputer` object with many helpful functions
describing properties of the created computer.

This will use the local hostname of the machine running this code as the computer name.
It will create the computer in AD's default `Computers` container.

It enables `AES256-SHA1` as an encryption type for both receiving and initiating kerberos
contexts, and it configures `<local hostname>.<domain dns name>` as the hostname of the
computer in AD and registers the default `HOST` service.

It then writes kerberos keys for the new computer account to `/etc/krb5.keytab`, which is
the default location for kerberos keytabs.

This all enables the account to be used for authenticating with other domain resources as a client
over protocols like SMB and LDAP using kerberos, as well as receiving incoming kerberos authentication
as a server for things like SSH. This is because the `HOST` service encapsulates many standard services
in the domain.

However, it is still up to the caller to do things like configure sshd to utilize the keytab.

### Join the domain with customization of the account for security reasons

A number of customizations exist for security reasons.

You can change things like the encryption types enabled on the account to support older clients.
You can also change location where the account is created when joining a domain in order to use
a less privileged user for the act of joining. Locations can be LDAP distinguished names or windows
path style canonical names.

You can also set the computer name if you have a desired naming scheme. This will impact the hostnames
configured in the domain for the computer.
```
from ms_active_directory import join_ad_domain, ADEncryptionType

domain = 'example.com'
less_privileged_user = 'ops-manager@example.com'
password = 'password2'
# ldap-style relative distinguished name of a location
less_privileged_loc = 'OU=service-machines,OU=ops'
computer_name = 'workstation10'

legacy_enc_type = ADEncryptionType.RC4_HMAC
new_enc_type = ADEncryptionType.AES256_CTS_HMAC_SHA1_96

comp = join_ad_domain(domain, less_privileged_user, password, computer_name=computer_name,
                      computer_location=less_privileged_loc, computer_encryption_types=[legacy_enc_type, new_enc_type])
                      
alt_format_loc = '/ops/service-machines'
comp = join_ad_domain(domain, less_privileged_user, password, computer_name=computer_name,
                      computer_location=alt_format_loc, computer_encryption_types=[legacy_enc_type, new_enc_type])

```

You can also manually set the computer password. The default is to generate a random 120
character password, but if you want to share this computer across services, and some cannot
interact with the generated kerberos keys, then you may wish to set a password manually.

You can also change where the kerberos keys are written to.
``` 
from ms_active_directory import join_ad_domain

domain = 'example.com'
user = 'ops-manager@example.com'
password = 'password2'
kerberos_key_location = '/usr/shared/keys/workstation-key.keytab'
computer_name = 'workstation10'
computer_password = 'workstation-shared-pw'

comp = join_ad_domain(domain, user, password, computer_key_file_path=kerberos_key_location,
                      computer_name=computer_name, computer_password=computer_password)
```

### Join the domain with different network or service settings
You can configure different hostnames for your computer when joining the
domain. This is useful when you have multiple different hostnames for
a single device, or want to use a computer name that doesn't match your
network name.

You can also configure services in order to restrict or broaden what is
supported by the computer when acting as a server (e.g. you can add `nfs`
if the machine will be an nfs server).

Joining will fail if another computer in the domain is using the services
you specify on any of the hostnames you specify in order to avoid conflicts
that cause undefined behavior.
``` 
from ms_active_directory import join_ad_domain

domain = 'example.com'
user = 'ops-manager@example.com'
password = 'password2'

services = ['HOST', 'nfs', 'cifs', 'HTTP']
computer_name = 'workstation10'
computer_host1 = 'central-mount-point.example.com'
computer_host2 = 'example-web-server.example.com'
comp = join_ad_domain(domain, user, password, computer_name=computer_name,
                      computer_hostnames=[computer_host1, computer_host2],
                      computer_services=services)
```


### Join using a domain object
You can use an `ADDomain` object to join the domain as well, using a `join` function.
This allows you to combine all of the functionality mentioned earlier around site-awareness,
server preferences, TLS settings, and network multi-tenancy with the domain joining
functionality mentioned in this section.

The parameters are all the same, except the domain need not be provided when using an
`ADDomain` object, so it just adds more functionality in exchange for a slightly less simple
workflow.

```
from ms_active_directory import ADDomain

domain = ADDomain('example.com', site='us-eastern-dc',
                  source_ip='10.25.21.30', dns_nameservers=['10.25.21.20'])

user = 'ops-manager@example.com'
password = 'password2'
less_privileged_loc = 'OU=service-machines,OU=ops'
services = ['HOST', 'nfs', 'cifs', 'HTTP']
computer_name = 'workstation10'

comp = domain.join(user, password, computer_hostnames=[computer_host1, computer_host2],
                   computer_services=services, computer_location=less_privileged_loc)
```

### Join the domain by taking over an existing account
For some setups, accounts may be pre-created and then taken over by the computers that will use them.

This can be done in order to greatly restrict the permissions of the user that is used for joining,
as they only need `RESET PASSWORD` permissions on the computer account, or `CHANGE PASSWORD` if
the current computer password is provided.
```
from ms_active_directory import ADDomain, join_ad_domain_by_taking_over_existing_computer

domain_dns_name = 'example.com'
site = 'us-eastern-dc'
existing_computer_name = 'precreated-comp'
user = 'single-account-admin@example.com'
password = 'password2'

computer_obj = join_ad_domain_by_taking_over_existing_computer(domain_dns_name, user, password,
                                                               ad_site=site, computer_name=existing_computer_name)
                                                               
# or use a domain object to use various power-user domain features
domain = ADDomain(domain_dns_name, site=site,
                  source_ip='10.25.21.30', dns_nameservers=['10.25.21.20'])
domain.join_by_taking_over_existing_computer(user, password, computer_name=existing_computer_name)
```

# Managing users, computers, and groups

The library provides a number of different functions for finding users, computers, and groups by different
identifiers, and for querying information about them.
It also has functions for checking their memberships and adding or removing users, computers, and groups
to or from groups.

## Looking up users, computers, groups, and information about them

Users, computers, and groups can both be looked up by one of:
- sAMAccountName
- distinguished name
- common name
- a generic "name" that will attempt the above 3
- an attribute

### Look up by sAMAccountName

A `sAMAccountName` is unique within a domain, and so looking up users or
groups by `sAMAccountName` returns a single result.
`sAMAccountName` was a user's windows logon name in older versions of windows,
and may be referred to as such in some documentation.

For computers, the standard convention is for their `sAMAccountName` to end with
a `$`, but many tools/docs leave that out. So if a `sAMAccountName` is specified
that does not end with a `$` and cannot be found, a lookup will also be
attempted after adding a `$` to the end.

When looking up users, computers, and groups, you can also query for additional information
about them by specifying a list of LDAP attributes.
``` 
from ms_active_directory import ADDomain
domain = ADDomain('example.com')
session = domain.create_session_as_user('username@example.com', 'password')

user = session.find_user_by_sam_name('user1', ['employeeID'])
group = session.find_group_by_sam_name('group1', ['gidNumber'])
# users and groups support a generic "get" for any attributes queried
print(user.get('employeeID'))
print(group.get('gidNumber'))
```

### Look up by distinguished name

A distinguished name is unique within a forest, and so looking up users or
groups by it returns a single result.
A distinguished name should not be escaped when provided to the search function.

When looking up users, computers, and groups, you can also query for additional information
about them by specifying a list of LDAP attributes.
``` 
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
```

### Look up by common name
A common name is not unique within a domain, and so looking up users or
groups by it returns a list of results, which may have 0 or more entries.

When looking up users, computers, and groups, you can also query for additional information
about them by specifying a list of LDAP attributes.
``` 
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
```

### Look up by generic name
You can also query by a generic "name", and the library will attempt to find a
unique user or group with that name. The library will either lookup by DN or will
attempt `sAMAccountName` and common name lookups depending on the name format.

If more than one result is found by common name and no result is found by
`sAMAccountName` then this will produce an error.
``` 
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
```

### Look up by attribute
You can also query for users, computers, or groups that possess a certain value for a
specified attribute. This can produce any number of results, so a list is
returned.
``` 
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
```

## Querying user, computer, and group membership
You can also look up the groups that a user belongs to, the groups that a computer belongs to,
or the groups that a group belongs to. Active Directory supports nested groups, which is why
there's `user->groups`, `computer->groups`, and `group->groups` mapping capability.

When querying the membership information for users or groups, the input type for any
user or group must either be a string name identifying the user, computer, or group as described in the prior
section, or must be an `ADUser`, `ADComputer`, or `ADGroup` object returned by one of the functions described
in the prior section.

Similarly to looking up users, computers, and groups, you can query for attributes of the parent groups
by providing a list of LDAP attributes to look up for them.

``` 
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
```

You can also query `users->groups`, `computers->groups`, and `groups->groups` to find the memberships of multiple
users, computers, and groups, and the library will make a minimal number of queries to determine membership;
it will be more efficient that doing a `user->groups` for each user (or similar for computers and groups).
The result will be a map that maps the input users or groups to lists of parent groups.

The input lists' elements must be the same format as what's provided when looking up group
memberships for a single user or group.
``` 
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
```

## Finding the members of groups

You can look up the members of one or more groups and get attributes about those
members.
```
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
```

You can also look up members recursively to handle nesting.
A maximum depth for lookups may be specified, but by default all
nesting will be enumerated.
``` 
from ms_active_directory import ADDomain, ADUser, ADGroup
domain = ADDomain('example.com')
session = domain.create_session_as_user('username@example.com', 'password')

# get emails of users and groups that are members
desired_attrs = ['mail'] 
group_name = 'has-groups-as-members'
groups_to_member_lists_maps = session.find_members_of_groups_recursive(group_name, desired_attrs)
```


## Adding users to groups
You can add users to groups by specifying a list of `ADUser` objects or string names of
AD users to be added to the groups, and a list of `ADGroup` objects or string names of AD
groups to add the users to.

If string names are specified, they'll be mapped to users/groups using the functions
discussed in the prior sections.

If a user is already in a group, this is idempotent and will not re-add them.

```
from ms_active_directory import ADDomain
domain = ADDomain('example.com')
session = domain.create_session_as_user('username@example.com', 'password')

user1_name = 'user1'
user2_name = 'user2'
group1_name = 'target-group1'
group2_name = 'target-group2'

session.add_users_to_groups([user1_name, user2_name],
                            [group1_name, group2_name])
```

By default, if we fail to add users to one of the groups specified, we'll attempt to rollback
and remove users from any groups they were added to. You can choose to forgo this and a list of
groups that users were successfully added to will be returned instead.
``` 
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
```

## Adding groups to groups

Adding groups to other groups works exactly the same way as adding users to groups, but
the function is called `add_groups_to_groups` and both inputs are lists of groups.

## Adding computers to groups

Adding computers to groups works exactly the same way as adding users to groups, but
the function is called `add_computers_to_groups` and the first input is a list of computers.

## Removing users, computers, or groups from groups

Removing users, computers, or groups from groups works identically to adding users, computers, or groups to groups,
including input format, idempotency, and rollback functionality.
The only difference is that the functions are called `remove_users_from_groups`, `remove_computers_from_groups`, and
`remove_groups_from_groups` instead.


## Updating user, computer, or group attributes.
You can use this library to modify the values of various LDAP attributes on
users, computers, groups, or generic objects.

Users, computers, and groups provide the convenient name lookup functionality mentioned above,
while for generic objects you either need to pass an `ADObject` or a distinguished name.

### Appending to one or more attributes
You can atomically append values to multi-valued attributes, such as `accountNameHistory`.
This allows you to update their values without needing to know the current value or worry
about race conditions, as it's handled server-side.
```
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
```
You can also perform these actions on groups and objects using the similarly named
functions `atomic_append_to_attribute_for_group`, `atomic_append_to_attributes_for_group`,
`atomic_append_to_attribute_for_computer`, `atomic_append_to_attributes_for_computer`,
`atomic_append_to_attribute_for_object`, and `atomic_append_to_attributes_for_object`.

### Overwriting one or more attributes
If you want to totally replace the value of an attribute, that's supported as well.
This can be done for single-valued or multi-valued attributes.

```
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
```
You can also perform these actions on groups and objects using the similarly named
functions, just like with appending.

# Discovering and Managing Trusted Domains

You can discover trusted domains using a session, and check properties about them.
```
from ms_active_directory import ADDomain
domain = ADDomain('example.com')
session = domain.create_session_as_user('username@example.com', 'password')

trusted_domains = session.find_trusted_domains_for_domain()

# split domains up based on trust type
trusted_mit_domains = [dom for dom in trusted_domains if dom.is_mit_trust()]
trusted_ad_domains = [dom for dom in trusted_domains if dom.is_active_directory_domain_trust()]

# print a few attributes that may be relevant
for ad_dom in trusted_ad_domains:
    print('FQDN: {}'.format(ad_dom.get_netbios_name()))
    print('Netbios name: {}'.format(ad_dom.get_netbios_name()))
    print('Disabled: {}'.format(ad_dom.is_disabled())
    print('Bi-directional: {}'.format(ad_dom.is_bidirectional_trust())
    print('Transitive: {}'.format(ad_dom.is_transitive_trust())
```

You can also convert AD domains that are trusted into fully usable `ADDomain`
objects for the purpose of creating sessions and looking up information there.
``` 
from ms_active_directory import ADDomain
from ldap3 import NTLM
domain = ADDomain('example.com')
widely_trusted_user = 'example.com\\org-admin'
password = 'password'

primary_session = domain.create_session_as_user(widely_trusted_user, password,
                                                authentication_mechanism=NTLM)

# get our trusted AD domains
trusted_domains = session.find_trusted_domains_for_domain()
trusted_ad_domains = [dom for dom in trusted_domains if dom.is_active_directory_domain_trust()]

# convert them into domains where our user should be trusted
domains_our_user_can_auth_with = []
for trusted_dom in trusted_ad_domains:
    if trusted_dom.trusts_primary_domain() and not trusted_dom.is_disabled():
        full_domain = trusted_dom.convert_to_ad_domain()
        domains_our_user_can_auth_with.append(full_domain)

# create sessions so we can search across many domains
all_user_sessions = [primary_session]
for dom in domains_our_user_can_auth_with:
    # SASL is needed for cross-domain authentication in general
    session = dom.create_session_as_user(widely_trusted_user, password,
                                         authentication_mechanism=NTLM)
    all_user_sessions.append(session)                                     
```

You can convert an existing authenticated session with one domain into an
authenticated session with a trusted AD domain that trusts the first domain.
```
from ms_active_directory import ADDomain
from ldap3 import NTLM
domain = ADDomain('example.com')
widely_trusted_user = 'example.com\\org-admin'
password = 'password'

primary_session = domain.create_session_as_user(widely_trusted_user, password,
                                                authentication_mechanism=NTLM)

# get our trusted AD domains
trusted_domains = session.find_trusted_domains_for_domain()
# filter for a domain being AD and it trusting the primary domain
trusted_ad_domains = [dom for dom in trusted_domains if dom.is_active_directory_domain_trust()
                      and dom.trusts_primary_domain()]

# create a new session with the trusted domain using our existing primary domain session,
# and use it to look up users/groups/etc. in the other domain
transferred_session = trusted_ad_domains[0].create_transfer_session_to_trusted_domain(primary_session)
transferred_session.find_user_by_name('other-domain-user')
```

You can also automatically have a session create sessions for all its trusted domains
that trust the session's domain.
```
from ms_active_directory import ADDomain
from ldap3 import NTLM
domain = ADDomain('example.com')
widely_trusted_user = 'example.com\\org-admin'
password = 'password'

primary_session = domain.create_session_as_user(widely_trusted_user, password,
                                                authentication_mechanism=NTLM)

# find a user that we know exists somewhere, but not the primary domain
user_to_find = 'some-lost-user'
# by default this filters to AD domains, and further filters to domains that trust the session's domain
# if the user used for the session is from the session's domain (which they are in this
# example)
trust_sessions = primary_session.create_transfer_sessions_to_all_trusted_domains()
user = None
for session in trust_sessions:
    user = session.find_user_by_name(user_to_find)
    if user is not None:
        print('Found user in {}'.format(session.get_domain_dns_name()))
        break
```