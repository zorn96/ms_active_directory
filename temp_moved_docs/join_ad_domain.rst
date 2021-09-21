Help on function join_ad_domain in module ms_active_directory.core.ad_domain:

join_ad_domain(domain_dns_name: str, admin_username: str, admin_password: str, authentication_mechanism: str = 'SIMPLE', ad_site: str = None, computer_name: str = None, computer_location: str = None, computer_password: str = None, computer_encryption_types: List[Union[str, ms_active_directory.environment.security.security_config_constants.ADEncryptionType]] = None, computer_hostnames: List[str] = None, computer_services: List[str] = None, supports_legacy_behavior: bool = False, computer_key_file_path: str = '/etc/krb5.keytab', **additional_account_attributes) -> ms_active_directory.core.managed_ad_objects.ManagedADComputer
    A super simple 'join a domain' function that requires minimal input - the domain dns name and admin credentials
    to use in the join process.
    Given those basic inputs, the domain's nearest controllers are automatically discovered and an account is made
    with strong security settings. The account's attributes follow AD naming conventions based on the computer's
    hostname by default.
    :param domain_dns_name: The DNS name of the domain being joined.
    :param admin_username: The username of a user or computer with the rights to create the computer.
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
    :param computer_location: The location in which to create the computer. This may be specified as an LDAP-style
                              relative distinguished name (e.g. OU=ServiceMachines,OU=Machines) or a windows path
                              style canonical name (e.g. example.com/Machines/ServiceMachines).
                              If not specified, defaults to CN=Computers which is the standard default for AD.
    :param computer_password: The password to set for the computer when taking it over. If not specified, a random
                              120 character password will be generated and set.
    :param computer_encryption_types: A list of encryption types, based on the ADEncryptionType enum, to enable on
                                      the account created. These may be strings or enums; if they are strings,
                                      they should be strings of the encryption types as written in kerberos
                                      RFCs or in AD management tools, and we will try to map them to enums and
                                      raise an error if they don't match any supported values.
                                      AES256-SHA1, AES128-SHA1, and RC4-HMAC encryption types are supported. DES
                                      encryption types aren not.
                                      If not specified, defaults to [AES256-SHA1].
    :param computer_hostnames: Hostnames to set for the computer. These will be used to set the dns hostname
                               attribute in AD. If not specified, the computer hostnames will default to
                               [`computer_name`, `computer_name`.`domain`] which is the AD standard default.
    :param computer_services: Services to enable on the computers hostnames. These services dictate what clients
                              can get kerberos tickets for when communicating with this computer, and this property
                              is used with `computer_hostnames` to set the service principal names for the computer.
                              For example, having `nfs` specified as a service principal is necessary if you want
                              to run an NFS server on this computer and have clients get kerberos tickets for
                              mounting shares; having `ssh` specified as a service principal is necessary for
                              clients to request kerberos tickets for sshing to the computer.
                              If not specified, defaults to `HOST` which is the standard AD default service.
                              `HOST` covers a wide variety of services, including `cifs`, `ssh`, and many others
                              depending on your domain. Determining exactly what services are covered by `HOST`
                              in your domain requires checking the aliases set on a domain controller.
    :param supports_legacy_behavior: If `True`, then an error will be raised if the computer name is longer than
                                     15 characters (not including the trailing $). This is because various older
                                     systems such as NTLM, certain UNC path applications, Netbios, etc. cannot
                                     use names longer than 15 characters. This name cannot be changed after
                                     creation, so this is important to control at creation time.
                                     If not specified, defaults to `False`.
    :param computer_key_file_path: The path of where to write the keytab file for the computer after taking it over.
                                   This will include keys for both user and server keys for the computer.
                                   If not specified, defaults to /etc/krb5.keytab
    :param additional_account_attributes: Additional keyword argument can be specified to set other LDAP attributes
                                          of the computer that are not covered above, or where the above controls
                                          are not sufficiently granular. For example, `userAccountControl` could
                                          be used to set the user account control values for the computer if it's
                                          desired to set it differently from the default (e.g. create a computer
                                          in a disabled state and enable it later).
    :returns: A ManagedADComputer object representing the computer created.

