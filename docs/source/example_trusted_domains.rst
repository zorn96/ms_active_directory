Finding and Working With Trusted Domains
##########################################


You can discover trusted domains using a session, and check properties about them.
::

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

Turning Trusted Domains into ``ADDomains``
------------------------------------------

You can also convert AD domains that are trusted into fully usable ``ADDomain``
objects for the purpose of creating sessions and looking up information there.
::

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


Transferring Sessions Across Domains
------------------------------------
You can convert an existing authenticated session with one domain into an
authenticated session with a trusted AD domain that trusts the first domain.
::

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


Expanding A Session To All Its Trusted Domains
----------------------------------------------
You can also automatically have a session create sessions for all its trusted domains
that trust the session's domain.
::

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
