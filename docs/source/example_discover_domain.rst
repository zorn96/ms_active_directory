Discovering a Domain
####################


The library supports discovering LDAP and Kerberos servers within a domain using special DNS
entries defined for Active Directory.

Smart Defaults
--------------
By default, it will use the system DNS configuration, find LDAP servers that support TLS, and sort
LDAP and Kerberos servers by the RTT to communicate with them.

Here's an example of creating a simple configuration and working with server discovery.
::

    from ms_active_directory import ADDomain

    example_domain_dns_name = 'example.com'
    domain = ADDomain(example_domain_dns_name)
    ldap_servers = domain.get_ldap_uris()
    kerberos_servers = domain.get_kerberos_uris()

    # re-discover servers in dns and sort them by RTT again at a later time to pick up changes
    domain.refresh_ldap_server_discovery()
    domain.refresh_kerberos_server_discovery()


Site Awareness and Flexible DNS
-------------------------------
The library also supports site awareness, which will result in only discovering servers within a specified
Active Directory Site. You can also specify alternative DNS nameservers to use instead of the system ones.

Here's an example of specifying an AD site and alternative DNS server.
::

    from ms_active_directory import ADDomain

    example_domain_dns_name = 'example.com'
    site_name = 'us-eastern-datacenter'
    domain = ADDomain(example_domain_dns_name, site=site_name,
                      dns_nameservers=['eastern-private-dns-01.local'])


Network Multi-Tenancy and Security Support
------------------------------------------
You can also specify exactly which LDAP or Kerberos servers should be used, and skip discovery.
Additional configurations are available such as configuring the CA file path to use for
trust, and the source IP to use for outbound traffic to the domain, which is helpful when
there are firewall rules in place, or when a machine has both private and public IP addresses.


Here's an example of specifying which servers to communicate with, and CA certs to secure that communication.
::

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


Local System Configuration
------------------------------------------
By default, you'll need to configure your local system files to enable kerberos authentication to work properly.
However, you can also automatically set up the krb5 configuration when creating a domain object.
::
    from ms_active_directory import ADDomain

    example_domain_dns_name = 'example.com'
    # set up the local system krb5 config based on discovered kerberos uris
    domain = ADDomain(example_domain_dns_name,
                      auto_configure_kerberos_client=True)

The file configured will be ``/etc/krb5.conf`` on posix systems (e.g. macOS, Ubuntu), and on windows both
``/winnt/krb5.ini`` and ``/windows/krb5.ini`` will be configured for backwards compatibility.
By default, a new kerberos realm configuration will be merged into these files if they exist, or new files
will be created if none exists.

If you want to update a different configuration file, or if you want to overwrite the file instead of updating it,
or if you want to set things like a default realm, you can also directly call the function for configuring the
local system.
::
    from ms_active_directory.environment.kerberos.kerberos_client_configurer import update_system_kerberos_configuration_for_domains
    from ms_active_directory import ADDomain

    example_domain_dns_name = 'example.com'
    domain = ADDomain(example_domain_dns_name)

    # overwrite the existing file instead of updating it
    update_system_kerberos_configuration_for_domains([domain], merge_with_existing_file=False)
    # update a file in a different location
    update_system_kerberos_configuration_for_domains([domain], krb5_location='/etc/user_100/krb5.conf')
    # set a default authentication realm
    update_system_kerberos_configuration_for_domains([domain], default_domain=domain)


Note: if multiple ``ADDomain`` objects all attempt to configure the local system kerberos file, only one will "win".
This means that if they have different sites specified, or used different source addresses on a network where
kdc reachability is reliant on that source address, having a single ``ADDomain`` object automatically configure
the krb5 configuration file can be risky.

In these scenarios, it's recommended that you manually write the krb5 configuration or that you set up an ``ADDomain``
object with kerberos uris for the entire domain and use that to initiate the auto-configuration.
