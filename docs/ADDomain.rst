Help on class ADDomain in module ms_active_directory.core.ad_domain:

class ADDomain(builtins.object)
 |  ADDomain(domain: str, site: str = None, ldap_servers_or_uris: List = None, kerberos_uris: List[str] = None, encrypt_connections: bool = True, ca_certificates_file_path: str = None, discover_ldap_servers: bool = True, discover_kerberos_servers: bool = True, dns_nameservers: List[str] = None, source_ip: str = None, netbios_name: str = None)
 |  
 |  Methods defined here:
 |  
 |  __init__(self, domain: str, site: str = None, ldap_servers_or_uris: List = None, kerberos_uris: List[str] = None, encrypt_connections: bool = True, ca_certificates_file_path: str = None, discover_ldap_servers: bool = True, discover_kerberos_servers: bool = True, dns_nameservers: List[str] = None, source_ip: str = None, netbios_name: str = None)
 |      Initialize an interface for defining an AD domain and interacting with it.
 |      :param domain: The DNS name of the Active Directory domain that this object represents.
 |      :param site: The Active Directory site to operate within. This is only relevant if LDAP or
 |                   kerberos servers are discovered in DNS, as there's site-specific records.
 |                   If set, only hosts within the specified site will be used.
 |      :param ldap_servers_or_uris: A list of either Server objects from the ldap3 library, or
 |                                   string LDAP uris. If specified, they will be used to establish
 |                                   sessions with the domain.
 |      :param kerberos_uris: A list of string kerberos server uris. These can be IPs (and the default
 |                            kerberos port of 88 will be used) or IP:port combinations.
 |      :param encrypt_connections: Whether or not LDAP connections with the domain will be secured
 |                                  using TLS. This must be True for join functionality to work,
 |                                  as passwords can only be set over secure connections.
 |                                  If not specified, defaults to True. If LDAP server objects are
 |                                  provided with ssl enabled or ldaps:// uris are provided, then
 |                                  connections to those servers will be encrypted because of the
 |                                  inherent behavior of such configurations.
 |      :param ca_certificates_file_path: A path to CA certificates to be used to establish trust
 |                                        with LDAP servers when securing connections. If not
 |                                        specified, then TLS will not check the peer certificate.
 |                                        If LDAP server objects are specified, then their TLS
 |                                        settings will be used rather than anything set in this
 |                                        variable. It is only used when discovering servers or
 |                                        using string URIs, so Server objects can be used if
 |                                        different CAs sign different servers' certificates
 |                                        due to regional CAs or something similar.
 |                                        If not specified, defaults to None.
 |      :param discover_ldap_servers: If true, and LDAP servers/uris are not specified, then LDAP
 |                                    servers for the domain will be discovered in DNS.
 |                                    If not specified, defaults to True.
 |      :param discover_kerberos_servers: If true, and kerberos uris are not specified, then kerberos
 |                                        servers for the domain will be discovered in DNS.
 |                                        If not specified, defaults to True.
 |      :param dns_nameservers: A list of strings indicating the IP addresses of DNS servers to use
 |                              when discovering servers for the domain. These may be IPv4 or IPv6
 |                              addresses.
 |                              If not specified, defaults to what's configured in /etc/resolv.conf on
 |                              POSIX systems, and extracting nameservers from registry keys on windows.
 |                              Defaults to None.
 |      :param source_ip: A source IP address to use for both DNS and LDAP connections established for
 |                        this domain. If not specified, defaults to automatic assignment of IP using
 |                        underlying system networking.
 |                        Defaults to None.
 |      :param netbios_name: The netbios name of this domain, which is relevant for a variety of functions.
 |                           If this is set, then we won't search the domain for the information.
 |                           This can be set by users, but isn't needed. It's primarily here to avoid
 |                           extra lookups when creating ADDomain objects from ADTrustedDomain objects, as
 |                           the netbios name is already known.
 |  
 |  __repr__(self)
 |      Return repr(self).
 |  
 |  __str__(self)
 |      Return str(self).
 |  
 |  create_ldap_connection_as_computer(self, computer_name: str, computer_password: str = None, check_name_format: bool = True, authentication_mechanism: str = 'GSSAPI', **kwargs) -> ldap3.core.connection.Connection
 |      Create an LDAP connection with AD domain authenticated as the specified computer.
 |      :param computer_name: The name of the computer to use when authenticating with the domain.
 |      :param computer_password: Optional, the password of the computer to use when authenticating with the domain.
 |                                If using an authentication mechanism like NTLM, this must be specified. But for
 |                                authentication mechanisms such as kerberos or external, either `sasl_credentials`
 |                                can be specified as a keyword argument or default system credentials will be used
 |                                in accordance with the auth mechanism.
 |      :param check_name_format: If True, the `computer_name` will be processed to try and format it based on the
 |                                authentication mechanism in use. For NTLM we will try to format it as
 |                                `domain`\`computer_name`, and for Kerberos/GSSAPI we will try to format is ass
 |                                `computer_name`@`domain`.
 |                                Defaults to True.
 |      :param authentication_mechanism: An LDAP authentication mechanism or SASL mechanism. If 'SASL' is specified,
 |                                       then the keyword argument `sasl_mechanism` must also be specified. Valid values
 |                                       include all authentication mechanisms and SASL mechanisms from the ldap3
 |                                       library, such as SIMPLE, NTLM, KERBEROS, etc.
 |      :returns: A Connection object representing a ldap connection with the domain.
 |  
 |  create_ldap_connection_as_user(self, user: str = None, password: str = None, authentication_mechanism: str = None, **kwargs) -> ldap3.core.connection.Connection
 |      Create an LDAP connection with AD domain authenticated as the specified user.
 |  
 |  create_session_as_computer(self, computer_name: str, computer_password: str = None, check_name_format: bool = True, authentication_mechanism: str = 'GSSAPI', **kwargs) -> ms_active_directory.core.ad_session.ADSession
 |      Create a session with AD domain authenticated as the specified computer.
 |      :param computer_name: The name of the computer to use when authenticating with the domain.
 |      :param computer_password: Optional, the password of the computer to use when authenticating with the domain.
 |                                If using an authentication mechanism like NTLM, this must be specified. But for
 |                                authentication mechanisms such as kerberos or external, either `sasl_credentials`
 |                                can be specified as a keyword argument or default system credentials will be used
 |                                in accordance with the auth mechanism.
 |      :param check_name_format: If True, the `computer_name` will be processed to try and format it based on the
 |                                authentication mechanism in use. For NTLM we will try to format it as
 |                                `domain`\`computer_name`, and for Kerberos/GSSAPI we will try to format is ass
 |                                `computer_name`@`domain`.
 |                                Defaults to True.
 |      :param authentication_mechanism: An LDAP authentication mechanism or SASL mechanism. If 'SASL' is specified,
 |                                       then the keyword argument `sasl_mechanism` must also be specified. Valid values
 |                                       include all authentication mechanisms and SASL mechanisms from the ldap3
 |                                       library, such as SIMPLE, NTLM, KERBEROS, etc.
 |      :returns: An ADSession object representing a connection with the domain.
 |  
 |  create_session_as_user(self, user: str = None, password: str = None, authentication_mechanism: str = None, **kwargs) -> ms_active_directory.core.ad_session.ADSession
 |      Create a session with AD domain authenticated as the specified user.
 |  
 |  find_current_time(self, ldap_connection: ldap3.core.connection.Connection = None) -> datetime.datetime
 |      Find the current time for this domain. This is useful for detecting drift that can cause
 |      Kerberos and TLS issues.
 |      Optionally, an existing connection can be used. If one is not specified, an anonymous LDAP
 |      connection will be created and used.
 |      :param ldap_connection: An ldap3 connection to the domain, optional.
 |      :returns: A datetime object representing the time.
 |  
 |  find_functional_level(self, ldap_connection: ldap3.core.connection.Connection = None) -> 'domainFunctionality'
 |      Find the functional level for this domain.
 |      Optionally, an existing connection can be used. If one is not specified, an anonymous LDAP
 |      connection will be created and used.
 |      :param ldap_connection: An ldap3 connection to the domain, optional.
 |      :returns: An ADVersion enum indicating the functional level.
 |  
 |  find_netbios_name(self, ldap_connection: ldap3.core.connection.Connection = None, force_refresh: bool = False) -> str
 |      Find the netbios name for this domain. Renaming a domain is a huge task and is incredibly rare,
 |      so this information is cached when first read, and it only re-read if specifically requested.
 |      Optionally, an existing connection can be used. If one is not specified, an anonymous LDAP
 |      connection will be created and used.
 |      
 |      :param ldap_connection: An ldap3 connection to the domain, optional.
 |      :param force_refresh: If set to true, the domain will be searched for the information even if
 |                            it is already cached. Defaults to false.
 |      :returns: A string indicating the netbios name of the domain.
 |  
 |  find_supported_sasl_mechanisms(self, ldap_connection: ldap3.core.connection.Connection = None) -> List[str]
 |      Find the supported SASL mechanisms for this domain.
 |      Optionally, an existing connection can be used. If one is not specified, an anonymous LDAP
 |      connection will be created and used.
 |      :param ldap_connection: An ldap3 connection to the domain, optional.
 |      :returns: A list of strings indicating the supported SASL mechanisms for the domain.
 |                ex: ['GSSAPI', 'GSS-SPNEGO', 'EXTERNAL']
 |  
 |  find_trusted_domains(self, ldap_connection: ldap3.core.connection.Connection = None) -> List[ForwardRef('ADTrustedDomain')]
 |      Find the trusted domains for this domain.
 |      An LDAP connection is technically optional, as some domains allow enumeration of trust
 |      relationships by anonymous users, but a connection is likely needed. If one is not specified,
 |      an anonymous LDAP connection will be created and used.
 |      
 |      :param ldap_connection: An ldap3 connection to the domain, optional.
 |      :returns: A list of ADTrustedDomain objects
 |  
 |  get_domain_dns_name(self) -> str
 |  
 |  get_kerberos_uris(self) -> List[str]
 |  
 |  get_ldap_servers(self) -> List[ldap3.core.server.Server]
 |  
 |  get_ldap_uris(self) -> List[str]
 |  
 |  is_close_in_time_to_localhost(self, ldap_connection: ldap3.core.connection.Connection = None, allowed_drift_seconds: int = None) -> bool
 |      Check if we're close in time to the domain.
 |      This is primarily useful for kerberos and TLS negotiation health.
 |      Optionally, an existing connection can be used. If one is not specified, an anonymous LDAP
 |      connection will be created and used.
 |      :param ldap_connection: An ldap3 connection to the domain, optional.
 |      :param allowed_drift_seconds: The number of seconds considered "close", defaults to 5 minutes.
 |                                    5 minutes is the standard allowable drift for kerberos.
 |      :returns: A boolean indicating whether we're within allowed_drift_seconds seconds of the domain time.
 |  
 |  join(self, admin_username: str, admin_password: str, authentication_mechanism: str = 'SIMPLE', computer_name: str = None, computer_location: str = None, computer_password: str = None, computer_encryption_types: List[Union[str, ms_active_directory.environment.security.security_config_constants.ADEncryptionType]] = None, computer_hostnames: List[str] = None, computer_services: List[str] = None, supports_legacy_behavior: bool = False, computer_key_file_path: str = '/etc/krb5.keytab', **additional_account_attributes) -> ms_active_directory.core.managed_ad_objects.ManagedADComputer
 |      A super simple 'join the domain' function that requires minimal input - just admin user credentials
 |      to use in the join process.
 |      Given those basic inputs, the domain's settings are used to establish a connection, and an account is made
 |      with strong security settings. The account's attributes follow AD naming conventions based on the computer's
 |      hostname by default.
 |      :param admin_username: The username of a user or computer with the rights to create the computer.
 |                             This username should be formatted based on the authentication protocol being used.
 |                             For example, DOMAIN\username for NTLM as opposed to username@DOMAIN for GSSAPI, or
 |                             a distinguished name for SIMPLE.
 |                             If `old_computer_password` is specified, then this account only needs permission to
 |                             change the password of the computer being taken over, which is different from the reset
 |                             password permission.
 |      :param admin_password: The password for the user. Optional, as SASL authentication mechanisms can use
 |                             `sasl_credentials` specified as a keyword argument, and things like KERBEROS will use
 |                             default system kerberos credentials if they're available.
 |      :param authentication_mechanism: An LDAP authentication mechanism or SASL mechanism. If 'SASL' is specified,
 |                                       then the keyword argument `sasl_mechanism` must also be specified. Valid values
 |                                       include all authentication mechanisms and SASL mechanisms from the ldap3
 |                                       library, such as SIMPLE, NTLM, KERBEROS, etc.
 |      :param computer_name: The name of the computer to take over in the domain. This should be the sAMAccountName
 |                            of the computer, though if computer has a trailing $ in its sAMAccountName and that is
 |                            omitted, that's ok. If not specified, we will attempt to find a computer with a name
 |                            matching the local system's hostname.
 |      :param computer_location: The location in which to create the computer. This may be specified as an LDAP-style
 |                                relative distinguished name (e.g. OU=ServiceMachines,OU=Machines) or a windows path
 |                                style canonical name (e.g. example.com/Machines/ServiceMachines).
 |                                If not specified, defaults to CN=Computers which is the standard default for AD.
 |      :param computer_password: The password to set for the computer when taking it over. If not specified, a random
 |                                120 character password will be generated and set.
 |      :param computer_encryption_types: A list of encryption types, based on the ADEncryptionType enum, to enable on
 |                                        the account created. These may be strings or enums; if they are strings,
 |                                        they should be strings of the encryption types as written in kerberos
 |                                        RFCs or in AD management tools, and we will try to map them to enums and
 |                                        raise an error if they don't match any supported values.
 |                                        AES256-SHA1, AES128-SHA1, and RC4-HMAC encryption types are supported. DES
 |                                        encryption types aren not.
 |                                        If not specified, defaults to [AES256-SHA1].
 |      :param computer_hostnames: Hostnames to set for the computer. These will be used to set the dns hostname
 |                                 attribute in AD. If not specified, the computer hostnames will default to
 |                                 [`computer_name`, `computer_name`.`domain`] which is the AD standard default.
 |      :param computer_services: Services to enable on the computers hostnames. These services dictate what clients
 |                                can get kerberos tickets for when communicating with this computer, and this property
 |                                is used with `computer_hostnames` to set the service principal names for the computer.
 |                                For example, having `nfs` specified as a service principal is necessary if you want
 |                                to run an NFS server on this computer and have clients get kerberos tickets for
 |                                mounting shares; having `ssh` specified as a service principal is necessary for
 |                                clients to request kerberos tickets for sshing to the computer.
 |                                If not specified, defaults to `HOST` which is the standard AD default service.
 |                                `HOST` covers a wide variety of services, including `cifs`, `ssh`, and many others
 |                                depending on your domain. Determining exactly what services are covered by `HOST`
 |                                in your domain requires checking the aliases set on a domain controller.
 |      :param supports_legacy_behavior: If `True`, then an error will be raised if the computer name is longer than
 |                                       15 characters (not including the trailing $). This is because various older
 |                                       systems such as NTLM, certain UNC path applications, Netbios, etc. cannot
 |                                       use names longer than 15 characters. This name cannot be changed after
 |                                       creation, so this is important to control at creation time.
 |                                       If not specified, defaults to `False`.
 |      :param computer_key_file_path: The path of where to write the keytab file for the computer after taking it over.
 |                                     This will include keys for both user and server keys for the computer.
 |                                     If not specified, defaults to /etc/krb5.keytab
 |      :param additional_account_attributes: Additional keyword argument can be specified to set other LDAP attributes
 |                                            of the computer that are not covered above, or where the above controls
 |                                            are not sufficiently granular. For example, `userAccountControl` could
 |                                            be used to set the user account control values for the computer if it's
 |                                            desired to set it differently from the default (e.g. create a computer
 |                                            in a disabled state and enable it later).
 |      :returns: A ManagedADComputer object representing the computer created.
 |  
 |  join_by_taking_over_existing_computer(self, admin_username: str, admin_password: str = None, authentication_mechanism: str = 'SIMPLE', computer_name: str = None, computer_password: str = None, old_computer_password: str = None, computer_key_file_path: str = '/etc/krb5.keytab', **additional_connection_attributes) -> ms_active_directory.core.managed_ad_objects.ManagedADComputer
 |      A super simple 'join the domain' function that requires minimal input - just admin user credentials
 |      to use in the join process.
 |      Given those basic inputs, the domain's settings are used to establish a connection, and an account is made
 |      with strong security settings. The account's attributes follow AD naming conventions based on the computer's
 |      hostname by default.
 |      :param admin_username: The username of a user or computer with the rights to reset the password of the computer
 |                             being taken over.
 |                             This username should be formatted based on the authentication protocol being used.
 |                             For example, DOMAIN\username for NTLM as opposed to username@DOMAIN for GSSAPI, or
 |                             a distinguished name for SIMPLE.
 |                             If `old_computer_password` is specified, then this account only needs permission to
 |                             change the password of the computer being taken over, which is different from the reset
 |                             password permission.
 |      :param admin_password: The password for the user. Optional, as SASL authentication mechanisms can use
 |                             `sasl_credentials` specified as a keyword argument, and things like KERBEROS will use
 |                             default system kerberos credentials if they're available.
 |      :param authentication_mechanism: An LDAP authentication mechanism or SASL mechanism. If 'SASL' is specified,
 |                                       then the keyword argument `sasl_mechanism` must also be specified. Valid values
 |                                       include all authentication mechanisms and SASL mechanisms from the ldap3
 |                                       library, such as SIMPLE, NTLM, KERBEROS, etc.
 |      :param computer_name: The name of the computer to take over in the domain. This should be the sAMAccountName
 |                            of the computer, though if computer has a trailing $ in its sAMAccountName and that is
 |                            omitted, that's ok. If not specified, we will attempt to find a computer with a name
 |                            matching the local system's hostname.
 |      :param computer_password: The password to set for the computer when taking it over. If not specified, a random
 |                                120 character password will be generated and set.
 |      :param old_computer_password: The current password of the computer being taken over. If specified, the action
 |                                    of taking over the computer will use a "change password" operation, which is less
 |                                    privileged than a "reset password" operation. So specifying this reduces the
 |                                    permissions needed by the user specified.
 |      :param computer_key_file_path: The path of where to write the keytab file for the computer after taking it over.
 |                                     This will include keys for both user and server keys for the computer.
 |                                     If not specified, defaults to /etc/krb5.keytab
 |      :param additional_connection_attributes: Additional keyword arguments may be specified for any properties of
 |                                               the `Connection` object from the `ldap3` library that is desired to
 |                                               be set on the connection used in the session created for taking over
 |                                               the computer. Examples include `sasl_credentials`, `client_strategy`,
 |                                               `cred_store`, and `pool_lifetime`.
 |      :returns: A ManagedADComputer object representing the computer taken over.
 |  
 |  refresh_kerberos_server_discovery(self)
 |      Re-discover Kerberos servers in DNS for the domain and redo the sorting by RTT.
 |      This can update our list of KDCs for future use by callers, allowing faster servers to be
 |      moved up in priority, unavailable servers to be removed from the list, and previously unavailable
 |      servers to be added.
 |  
 |  refresh_ldap_server_discovery(self)
 |      Re-discover LDAP servers in DNS for the domain and redo the sorting by RTT.
 |      This can update our list of LDAP servers for future connections, allowing faster servers to be
 |      moved up in priority, unavailable servers to be removed from the list, and previously unavailable
 |      servers to be added.
 |  
 |  set_kerberos_uris(self, kerberos_uris: List)
 |      Sets our kerberos server uris
 |  
 |  set_ldap_servers_or_uris(self, ldap_servers_or_uris: List)
 |      Set our list of LDAP servers or LDAP URIs. The list provided can be a list of
 |      Server objects, URIs, or a mixture.
 |  
 |  ----------------------------------------------------------------------
 |  Data descriptors defined here:
 |  
 |  __dict__
 |      dictionary for instance variables (if defined)
 |  
 |  __weakref__
 |      list of weak references to the object (if defined)

