``RawKerberosKey`` Objects
---------------------------

class RawKerberosKey(builtins.object)
 |  RawKerberosKey(enc_type: Union[ms_active_directory.environment.security.security_config_constants.ADEncryptionType, str], key_bytes: bytes)
 |  
 |  A raw kerberos key - containing only the generated shared secret and the encryption type.
 |  This does not contain any information about who's using it, its purpose, etc. and is tied
 |  only to the password used, the salt, and the encryption type. It can therefore be used to
 |  generate usable kerberos keys for either accepting or initiating GSS authentication.
 |  
 |  Methods defined here:
 |  
 |  __init__(self, enc_type: Union[ms_active_directory.environment.security.security_config_constants.ADEncryptionType, str], key_bytes: bytes)
 |      Initialize self.  See help(type(self)) for accurate signature.
 |  
 |  get_hex_encoded_key(self)
 |  
 |  get_key_bytes(self)
 |  
 |  get_raw_hex_encoded_key(self)
 |  
 |  uses_active_directory_supported_encryption_type(self)
 |  
 |  ----------------------------------------------------------------------
 |  Data descriptors defined here:
 |  
 |  __dict__
 |      dictionary for instance variables (if defined)
 |  
 |  __weakref__
 |      list of weak references to the object (if defined)

