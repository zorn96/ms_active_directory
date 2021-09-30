Discovering Additional Domain Resources
##########################################

The library supports discovering a wide variety of information about the domain beyond
the basics needed to communicate with it. This discovery doesn't require you to know any
niche information about Active Directory.

Discoverable resources include but are not limited to:

1. Supported SASL mechanisms, which is important for authentication
2. The current domain time, which is important for NTP synchronization
3. Domain Functional Level, which governs things like support encryption types
4. DNS servers
5. Issuing certificates for CAs in the domain

Finding supported SASL mechanisms
---------------------------------
Discovering SASL mechanisms can be done without needing to create a session
with a domain, as it's needed before authentication in many cases.
::

    from ms_active_directory import ADDomain
    domain = ADDomain('example.com')

    # might print "['EXTERNAL', 'DIGEST-MD5']"
    print(domain.find_supported_sasl_mechanisms())


Finding the current domain time
-------------------------------
Discovering the domain time can be done without needing to create a session
with a domain, as time synchronization is necessary for kerberos authentication
to succeed and can impact TLS negotiation as well.
::

    from ms_active_directory import ADDomain
    domain = ADDomain('example.com')

    # returns a python datetime object in utc time
    curr_time = domain.find_current_time()

    # allowed drift defaults to 5 minutes which is the kerberos standard,
    # but we can use a shorter window to detect drift before it causes an
    # outage. this returns a boolean
    synced = domain.is_close_in_time_to_localhost(allowed_drift_seconds=60)


Finding the domain functional level
-----------------------------------
Discovering the domain time can be done without needing to create a session
with a domain, as it can inform us as to what encryption types and TLS versions/ciphers
will be supported by the domain.
::

    from ms_active_directory import ADDomain
    domain = ADDomain('example.com')

    # find_functional_level returns an enum indicating the level.
    # decision making based on level should be done based on the
    # needs of your application
    print(domain.find_functional_level())


Finding DNS servers
--------------------
Discovering DNS servers requires an authenticated session with the domain,
as searching the records within the domain for computers that run a DNS
service is privileged.
::

    from ms_active_directory import ADDomain
    domain = ADDomain('example.com')

    session = domain.create_session_as_user('username@example.com', 'password')
    # returns a map that maps server hostnames -> ip addresses, where
    # the hostnames are computers running dns services
    dns_map = session.find_dns_servers_for_domain()
    ip_addrs = dns_map.values()
    hostnames = dns_map.keys()


Finding CA certificates
------------------------
Discovering DNS servers requires an authenticated session with the domain,
as searching the records within the domain for records that are indicated
as being certificate authorities is privileged.

::

    from ms_active_directory import ADDomain
    domain = ADDomain('example.com')

    session = domain.create_session_as_user('username@example.com', 'password')
    # returns a list of PEM-formatted strings representing the signing certificates
    # of all certificate authorities in the domain
    pem_certs = session.find_certificate_authorities_for_domain()

    # you can also get the certificates in DER format, which might be
    # preferred on windows
    der_certs = session.find_certificate_authorities_for_domain(pem_format=False)
