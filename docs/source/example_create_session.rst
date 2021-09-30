Creating a Session With a Domain
###################################


You can establish a session with the AD Domain on behalf of either a user or computer.

Broadly, any keyword arguments that would normally be supported when creating a ``Connection``
with the ``ldap3`` library are supported when creating a session, allowing
for flexibility while still providing an "it just works" option for
most users.

Support for Computer Authentication
------------------------------------
Computers default to using Kerberos SASL authentication, as SIMPLE authentication is
not support for computers with Active Directory.
To use kerberos, either ``gssapi`` or ``winkerberos`` must be
installed.

Here's an example of authenticating as a computer ::

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


You can also use other authentication mechanisms like NTLM.::

    from ldap3 import NTLM
    from ms_active_directory import ADDomain
    domain = ADDomain('example.com')

    ntlm_name = 'EXAMPLE.COM\\computer01'
    password = 'password1'
    session = domain.create_session_as_computer(ntlm_name, password, authentication_mechanism=NTLM)


Support for User Authentication
-------------------------------

You can authenticate as a user by using simple binds, or by using SASL
mechanisms or NTLM as computers do.
The default for users is simple binds.

Here's an example of using some different authentication mechanisms for the same user::

    from ldap3 import NTLM
    from ms_active_directory import ADDomain
    domain = ADDomain('example.com')

    session = domain.create_session_as_user('username@example.com', 'password')
    ntlm_session =  domain.create_session_as_user('username@example.com', 'password', authentication_mechanism=NTLM)

