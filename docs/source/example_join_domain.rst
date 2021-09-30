Joining an Active Directory Domain
##################################

The action of joining a computer to a domain is not a well-defined operation,
and so the exact mechanics of how you utilize the domain joining functionality
and how its outputs are integrated with the rest of your system will vary depending on
your use case.

This will try to cover some common examples.

Join the domain with default configurations for everything
------------------------------------------------------------
The default behavior requires only the domain name and the credentials of a user with
sufficient administrative rights to create computers within the domain.
::

    from ms_active_directory import join_ad_domain

    comp = join_ad_domain('example.com', 'Administrator@example.com', 'example-password')

The ``join_ad_domain`` function returns a ``ManagedADComputer`` object with many helpful functions
describing properties of the created computer.

This will use the local hostname of the machine running this code as the computer name.
It will create the computer in AD's default ``Computers`` container.

It enables ``AES256-SHA1`` as an encryption type for both receiving and initiating kerberos
contexts, and it configures ``<local hostname>.<domain dns name>`` as the hostname of the
computer in AD and registers the default ``HOST`` service.

It then writes kerberos keys for the new computer account to ``/etc/krb5.keytab``, which is
the default location for kerberos keytabs.

This all enables the account to be used for authenticating with other domain resources as a client
over protocols like SMB and LDAP using kerberos, as well as receiving incoming kerberos authentication
as a server for things like SSH. This is because the ``HOST`` service encapsulates many standard services
in the domain.

However, it is still up to the caller to do things like configure sshd to utilize the keytab.

Join the domain with customization of the account for security reasons
------------------------------------------------------------------------

A number of customizations exist for security reasons.

You can change things like the encryption types enabled on the account to support older clients.
You can also change location where the account is created when joining a domain in order to use
a less privileged user for the act of joining. Locations can be LDAP distinguished names or windows
path style canonical names.

You can also set the computer name if you have a desired naming scheme. This will impact the hostnames
configured in the domain for the computer.
::

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



You can also manually set the computer password. The default is to generate a random 120
character password, but if you want to share this computer across services, and some cannot
interact with the generated kerberos keys, then you may wish to set a password manually.

You can also change where the kerberos keys are written to.
::

    from ms_active_directory import join_ad_domain

    domain = 'example.com'
    user = 'ops-manager@example.com'
    password = 'password2'
    kerberos_key_location = '/usr/shared/keys/workstation-key.keytab'
    computer_name = 'workstation10'
    computer_password = 'workstation-shared-pw'

    comp = join_ad_domain(domain, user, password, computer_key_file_path=kerberos_key_location,
                          computer_name=computer_name, computer_password=computer_password)


Join the domain with different network or service settings
--------------------------------------------------------------
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
::

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



Join using a domain object
-----------------------------
You can use an ``ADDomain`` object to join the domain as well, using a ``join`` function.
This allows you to combine all of the functionality mentioned earlier around site-awareness,
server preferences, TLS settings, and network multi-tenancy with the domain joining
functionality mentioned in this section.

The parameters are all the same, except the domain need not be provided when using an
``ADDomain`` object, so it just adds more functionality in exchange for a slightly less simple
workflow.

::

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


Join the domain by taking over an existing account
----------------------------------------------------
For some setups, accounts may be pre-created and then taken over by the computers that will use them.

This can be done in order to greatly restrict the permissions of the user that is used for joining,
as they only need ``RESET PASSWORD`` permissions on the computer account, or ``CHANGE PASSWORD`` if
the current computer password is provided.
::

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

