# ms_active_directory - A Library for Integrating with Microsoft Active Directory
This is a library for integrating with Microsoft Active Directory domains.

It supports a variety of common, critical functionality for integration of computers
into a domain, including the ability to discover domain resources, optimize
communication for speed, join a computer to the domain, and look up information
about users and groups in the domain.

It primarily builds on the LDAP protocol, and supports LDAP over TLS with channel bindings,
and all LDAP basic, NTLM, and SASL authentication mechanisms supported by the `ldap3` python
library.

**Author**: Azaria Zornberg
\
**Email**: a.zornberg96@gmail.com


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

ntlm_name = 'EXAMPLE.COM\computer01'
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
The `join_ad_domain` function returns an `ADComputer` object with many helpful functions
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
a less privileged user for the act of joining.

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
                      computer_location=password, computer_encryption_types=[legacy_enc_type, new_enc_type])
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
