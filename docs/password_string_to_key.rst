Help on function password_string_to_key in module ms_active_directory.environment.kerberos.kerberos_raw_key_generator:

password_string_to_key(ad_encryption_type: ms_active_directory.environment.security.security_config_constants.ADEncryptionType, password_string: str, salt_string: str = None, iterations: int = None) -> ms_active_directory.core.ad_kerberos_keys.RawKerberosKey
    Given an encryption type, a string password, and optionally a string salt and an iteration count, generate and
    return a kerberos key for the specified encryption type using the other parameters.

