Help on function join_ad_domain_by_taking_over_existing_computer in module ms_active_directory.core.ad_domain:

join_ad_domain_by_taking_over_existing_computer(domain_dns_name: str, admin_username: str, admin_password: str, authentication_mechanism: str = 'SIMPLE', ad_site: str = None, computer_name: str = None, computer_password: str = None, old_computer_password: str = None, computer_key_file_path: str = '/etc/krb5.keytab', **additional_connection_attributes) -> ms_active_directory.core.managed_ad_objects.ManagedADComputer
    A super simple 'join a domain' function using pre-created computer accounts, which requires minimal input -
    the domain dns name and admin credentials to use in the join process.
    Specifying a computer name explicitly for the account to take over is also highly recommended.
    
    Given those basic inputs, the domain's nearest controllers are automatically discovered and the computer account
    with the specified computer name is found and taken over so it can represent the local system in the domain,
    and the local system can act as it.
    :param domain_dns_name: The DNS name of the domain being joined.
    :param admin_username: The username of a user or computer with the rights to reset the password of the computer
                           being taken over.
                           This username should be formatted based on the authentication protocol being used.
                           For example, DOMAIN\username for NTLM as opposed to username@DOMAIN for GSSAPI, or
                           a distinguished name for SIMPLE.
                           If `old_computer_password` is specified, then this account only needs permission to
                           change the password of the computer being taken over, which is different from the reset
                           password permission.
    :param admin_password: The password for the user. Optional, as SASL authentication mechanisms can use
                           `sasl_credentials` specified as a keyword argument, and things like KERBEROS will use
                           default system kerberos credentials if they're available.
    :param authentication_mechanism: An LDAP authentication mechanism or SASL mechanism. If 'SASL' is specified,
                                     then the keyword argument `sasl_mechanism` must also be specified. Valid values
                                     include all authentication mechanisms and SASL mechanisms from the ldap3
                                     library, such as SIMPLE, NTLM, KERBEROS, etc.
    :param ad_site: Optional. The site within the active directory domain where our communication should be confined.
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
    :param additional_connection_attributes: Additional keyword arguments may be specified for any properties of
                                             the `Connection` object from the `ldap3` library that is desired to
                                             be set on the connection used in the session created for taking over
                                             the computer. Examples include `sasl_credentials`, `client_strategy`,
                                             `cred_store`, and `pool_lifetime`.
    :returns: A ManagedADComputer object representing the computer taken over.

