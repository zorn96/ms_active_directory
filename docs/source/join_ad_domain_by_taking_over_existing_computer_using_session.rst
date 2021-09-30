Joining an AD Domain by taking over an existing computer using an existing session
--------------------------------------------------------------------------------------

To join the local machine to an AD Domain, you can use an ``ADDomain`` object and use its
function, but if you already have a pre-existing session from elsewhere, there's also a
standalone function that can be imported from the library directly as::

    >>> from ms_active_directory import join_ad_domain_by_taking_over_existing_computer_using_session

This function can be used to have a 1-line call to join the machine to the domain by taking over a pre-created computer
account. This is convenient for setups where the computer is
pre-created with a lot of settings so that the machines joining don't need to know what attribute values to set.

Taking over an existing computer returns the a ``ManagedADComputer`` object, and writes kerberos keys
to the local file system and such, but there's no option to specify things like services and dns hostnames as those are
read from the existing computer.

To take over a computer in this way, use the following function::


    join_ad_domain_by_taking_over_existing_computer_using_session(ad_session: ms_active_directory.core.ad_session.ADSession,
                                                                  computer_name=None, computer_password=None, old_computer_password=None,
                                                                  computer_key_file_path='/etc/krb5.keytab') -> ms_active_directory.core.managed_ad_objects.ManagedADComputer
        A fairly simple 'join a domain' function using pre-created accounts, which requires minimal input - an AD
        session. Specifying the name of the computer to takeover explicitly is also encouraged.

        Given those basic inputs, the domain's nearest controllers are automatically discovered and an account is found
        with the computer name specified.
        That account is then taken over so that it can be controlled by the local system, and kerberos keys and such are
        generated for it.

        By providing an AD session, one can build a connection to the domain however they so choose and then use it to
        join this computer, so you don't even need to necessarily use user credentials.
        :param ad_session: The ADSession object representing a connection with the domain to be joined.
        :param computer_name: The name of the computer to take over in the domain. This should be the sAMAccountName
                              of the computer, though if computer has a trailing $ in its sAMAccountName and that is
                              omitted, that's ok. If not specified, we will attempt to find a computer with a name
                              matching the local system's hostname.
        :param computer_password: The password to set for the computer when taking it over. If not specified, a random
                                  120 character password will be generated and set.
        :param old_computer_password: The current password of the computer being taken over. If specified, the action
                                      of taking over the computer will use a "change password" operation, which is less
                                      privileged than a "reset password" operation. So specifying this reduces the
                                      permissions needed by the user specified.
        :param computer_key_file_path: The path of where to write the keytab file for the computer after taking it over.
                                       This will include keys for both user and server keys for the computer.
                                       If not specified, defaults to /etc/krb5.keytab
        :returns: A ManagedADComputer object representing the computer taken over.
