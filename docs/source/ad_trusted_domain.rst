Help on class ADTrustedDomain in module ms_active_directory.core.ad_domain:

class ADTrustedDomain(builtins.object)
 |  ADTrustedDomain(primary_domain: ms_active_directory.core.ad_domain.ADDomain, trust_ldap_attributes: dict)
 |  
 |  Methods defined here:
 |  
 |  __init__(self, primary_domain: ms_active_directory.core.ad_domain.ADDomain, trust_ldap_attributes: dict)
 |      ADTrustedDomain objects represent a trustedDomain object found within an ADDomain.
 |      
 |      :param primary_domain: An ADDomain object representing the domain where this trusted domain object was found.
 |      :param trust_ldap_attributes: A dictionary of LDAP attributes for the trustedDomain.
 |  
 |  __repr__(self)
 |      Return repr(self).
 |  
 |  __str__(self)
 |      Return str(self).
 |  
 |  convert_to_ad_domain(self, site: str = None, ldap_servers_or_uris: List = None, kerberos_uris: List[str] = None, encrypt_connections: bool = True, ca_certificates_file_path: str = None, discover_ldap_servers: bool = True, discover_kerberos_servers: bool = True, dns_nameservers: List[str] = None, source_ip: str = None) -> ms_active_directory.core.ad_domain.ADDomain
 |      Convert this AD domain trust to an ADDomain object. This takes all of the same keyword arguments
 |      as creating an ADDomain object, and use the attributes of the primary domain where appropriate for
 |      network settings.
 |      
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
 |                              If not specified, defaults to the DNS nameservers configured in the
 |                              primary domain where this trusted domain was found because domains
 |                              that trust each other are mutually discoverable in each others'
 |                              DNS or must use a DNS that contains both of them.
 |                              If not specified and the primary domain has no nameservers set,
 |                              defaults to what's configured in /etc/resolv.conf on POSIX systems,
 |                              and extracting nameservers from registry keys on windows.
 |                              Can be set to an empty list to force use of the system defaults even
 |                              when the primary domain has dns_nameservers set.
 |      :param source_ip: A source IP address to use for both DNS and LDAP connections established for
 |                        this domain.
 |                        If not specified, defaults to the source IP used for the primary where
 |                        this trusted domain was found, because domains that trust each other are
 |                        mutually routable, and so the source IP used to talk to the primary domain
 |                        is assumed to also be the right default network identity for talking to
 |                        this domain.
 |                        If not specified and the primary domain has no source ip set, defaults to
 |                        automatic assignment of IP using underlying system networking.
 |                        Can be set to an empty string to force use of the system defaults even
 |                        when the primary domain has source_ip set.
 |      :returns: An ADDomain object representing this trusted domain as a complete domain with the
 |                corresponding functionality.
 |  
 |  create_transfer_session_to_trusted_domain(self, ad_session: ms_active_directory.core.ad_session.ADSession, converted_ad_domain: ms_active_directory.core.ad_domain.ADDomain = None, skip_validation: bool = False) -> ms_active_directory.core.ad_session.ADSession
 |      Create a session with this trusted domain that functionally transfers the authentication of a given session.
 |      This is useful for transferring a kerberos/ntlm session to create new sessions for querying in trusted domains
 |      without needing to provide credentials ever time.
 |      
 |      :param ad_session: The active directory session to transfer. This session will not be altered.
 |      :param converted_ad_domain: Optional. If a caller wants to specify information like an AD site, or ldap
 |                                  server preferences, or if the caller simply wants to avoid having DNS lookups
 |                                  and RTT measurements done every single time they transfer a session because they
 |                                  have a lot of sessions to transfer, then they can specify an ADDomain object
 |                                  that represents the converted ADTrustedDomain.
 |                                  If not specified, an ADDomain will be created for the trusted domain during
 |                                  transfer.
 |      :param skip_validation: Optional. If set to False, validation checks about the trusted domain being an AD domain
 |                              or the trusted domain trusting the primary domain for users originating from the
 |                              primary domain will be skipped. This can be set to True in scenarios where the trust
 |                              has been reconfigured on the trusted domain, but the primary domain has stale info,
 |                              to avoid needing to wait for changes to propagate to make use of the new trust.
 |                              If not specified, defaults to True.
 |      :returns: An ADSession representing the transferred authentication to the trusted domain.
 |      :raises: SessionTransferException If any validation fails when transferring the session.
 |      :raises: Other LDAP exceptions if the attempt to bind the transfer session in the trusted domain fails due to
 |               authentication issues (e.g. trying to use a non-transitive trust when transferring a user that is
 |               not from the primary domain, transferring across a one-way trust when skipping validation,
 |               transferring to a domain using SID filtering to restrict cross-domain users)
 |  
 |  get_fqdn(self) -> str
 |      Returns the FQDN of the trusted domain.
 |  
 |  get_netbios_name(self) -> str
 |      Returns the netbios name of the trusted domain.
 |  
 |  get_posix_offset(self) -> int
 |      Returns the posix offset for the trust relationship. This is specific to the primary domain.
 |  
 |  get_raw_trust_attributes_value(self) -> int
 |      Returns the raw trust attributes value, which is a bitstring indicating properties of the trust.
 |  
 |  is_active_directory_domain_trust(self) -> bool
 |      Returns True if the trusted domain is an Active Directory domain.
 |  
 |  is_bidirectional_trust(self) -> bool
 |      Returns True if the trust is mutual, meaning the primary domain trusts users from the trusted domain, and
 |      the trusted domain trusts users from the primary domain.
 |  
 |  is_cross_forest_trust(self) -> bool
 |      Returns True if the trust relationship is a cross-forest trust.
 |  
 |  is_cross_organization_trust(self) -> bool
 |      Returns True if the trust relationship is a cross-organization trust.
 |  
 |  is_disabled(self) -> bool
 |      Returns True if the trust relationship has been disabled.
 |  
 |  is_findable_via_netlogon(self) -> bool
 |      Returns True if the trusted domain is findable in netlogon and the trust works there.
 |  
 |  is_in_same_forest_as_primary_domain(self) -> bool
 |      Returns True if the trusted domain is in the same forest as the primary domain. For example,
 |      both "americas.my-corp.net" and "emea.my-corp.net" might be subdomains within the "my-corp.net"
 |      forest.
 |  
 |  is_mit_trust(self) -> bool
 |      Returns True if the trusted domain is an MIT Kerberos Realm.
 |  
 |  is_non_active_directory_windows_trust(self) -> bool
 |      Returns True if the trusted domain is a non-Active Directory windows domain.
 |  
 |  is_transitive_trust(self) -> bool
 |      Returns True if the trust relationship is transitive. If a relationship is transitive, then that means
 |      that if A trusts principals from B, and B trusts principals from C, then A will also trust principals from C
 |      even if it doesn't explicitly know that C exists.
 |      Cross-forest trusts are inherently transitive unless transitivity is disabled. Cross-domain trusts are not
 |      inherently transitive.
 |  
 |  is_trusted_by_primary_domain(self) -> bool
 |      Returns True if the primary domain trusts users originating in the trusted domain.
 |  
 |  mit_trust_uses_rc4_hmac_for(self) -> bool
 |      Returns True to indicate that this trusted MIT Kerberos Realm can use RC4-HMAC encryption.
 |      This is only relevant for MIT Kerberos Realms, and is a legacy attribute from a time when
 |      RC4-HMAC was not widely adopted, AES128/AES256 weren't standard in AD, and only the less secure
 |      single-DES encryption mechanisms were shared between MIT and AD by default.
 |  
 |  should_treat_as_external_trust(self) -> bool
 |      Returns True if the trusted domain is configured such that it should be explicitly treated as
 |      if the trusted domain is external to the forest of the primary domain, despite being within it.
 |  
 |  trusts_primary_domain(self) -> bool
 |      Returns True if the trusted domain trusts users originating in the primary domain.
 |  
 |  uses_sid_filtering(self) -> bool
 |      Returns True if this relationship employs SID filtering. This is common in forest trusts/transitive trusts
 |      in order to ensure some level of control over which users from other domains are allowed to operate within
 |      the primary domain.
 |  
 |  ----------------------------------------------------------------------
 |  Data descriptors defined here:
 |  
 |  __dict__
 |      dictionary for instance variables (if defined)
 |  
 |  __weakref__
 |      list of weak references to the object (if defined)

