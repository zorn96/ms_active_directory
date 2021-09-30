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
