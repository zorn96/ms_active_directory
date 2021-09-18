Help on function ad_password_string_to_key in module ms_active_directory.environment.kerberos.kerberos_raw_key_generator:

ad_password_string_to_key(ad_encryption_type: ms_active_directory.environment.security.security_config_constants.ADEncryptionType, ad_computer_name: str, ad_password: str, ad_domain_dns_name: str, ad_auth_realm: str = None) -> ms_active_directory.core.ad_kerberos_keys.RawKerberosKey
    Given an encryption type, a computer name, a password, and a domain, generate the raw kerberos key for an AD
    account. Optionally, a realm may be specified if the kerberos realm for the domain is not the domain itself
    (this may be the case for subdomains or when AD is not the central authentication for an environment).
    :param ad_encryption_type: The kerberos encryption type to use for generating the key.
    :param ad_computer_name: The name of the computer in AD. This is the sAMAccountName without the trailing $.
    :param ad_password: The password of the computer.
    :param ad_domain_dns_name: The DNS name of the AD domain where the computer exists.
    :param ad_auth_realm: The realm used by the domain for authentication. If not specified, defaults to the domain
                          in all captial letters.

