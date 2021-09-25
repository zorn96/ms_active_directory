Help on class ManagedADComputer in module ms_active_directory.core.managed_ad_objects:

class ManagedADComputer(ManagedADObject)
 |  ManagedADComputer(samaccount_name: str, domain: 'ADDomain', location: str = None, password: str = None, service_principal_names: List[str] = None, encryption_types: List[ms_active_directory.environment.security.security_config_constants.ADEncryptionType] = None, kvno: int = None)
 |  
 |  Method resolution order:
 |      ManagedADComputer
 |      ManagedADObject
 |      builtins.object
 |  
 |  Methods defined here:
 |  
 |  __init__(self, samaccount_name: str, domain: 'ADDomain', location: str = None, password: str = None, service_principal_names: List[str] = None, encryption_types: List[ms_active_directory.environment.security.security_config_constants.ADEncryptionType] = None, kvno: int = None)
 |      Initialize self.  See help(type(self)) for accurate signature.
 |  
 |  add_encryption_type_locally(self, encryption_type: ms_active_directory.environment.security.security_config_constants.ADEncryptionType)
 |      Adds an encryption type to the computer locally. This will generate new kerberos keys
 |      for the computer as a user and for all of the computer's service principal names using the
 |      new encryption type.
 |      This function does nothing if the encryption type is already on the computer.
 |      This function raises an exception if the computer's password is not set, as the password is
 |      needed to generate new kerberos keys.
 |      :param encryption_type: The encryption type to add to the computer.
 |  
 |  add_service_principal_name_locally(self, service_principal_name: str)
 |      Adds a service principal name to the computer locally. This will generate new kerberos keys
 |      for the computer to use to accept security contexts for the service principal name using
 |      all raw kerberos keys that the account has (and therefore all encryption types it has).
 |      This function does nothing if the service principal name is already on the computer.
 |      
 |      :param service_principal_name: The service principal name to add to the computer.
 |  
 |  get_computer_distinguished_name(self) -> str
 |      Get the LDAP distinguished name for the computer. This raises an exception if location is not
 |      set for the computer.
 |  
 |  get_computer_name(self) -> str
 |  
 |  get_encryption_types(self) -> List[ms_active_directory.environment.security.security_config_constants.ADEncryptionType]
 |  
 |  get_full_keytab_file_bytes_for_computer(self) -> bytes
 |      Get the raw bytes that would comprise a complete keytab file for this computer. The
 |      resultant bytes form a file that can be used to either accept GSS security contexts as a
 |      server for any protocol and hostname combinations defined in the service principal names,
 |      or initiate them as the computer with the computer's user principal name being the
 |      sAMAccountName.
 |  
 |  get_name(self) -> str
 |  
 |  get_server_kerberos_keys(self) -> List[ms_active_directory.core.ad_kerberos_keys.GssKerberosKey]
 |  
 |  get_server_keytab_file_bytes_for_computer(self) -> bytes
 |      Get the raw bytes that would comprise a server keytab file for this computer. The resultant
 |      bytes form a file that can be used to accept GSS security contexts as a server for any protocol
 |      and hostname combinations defined in the service principal names.
 |  
 |  get_service_principal_names(self) -> List[str]
 |  
 |  get_user_kerberos_keys(self) -> List[ms_active_directory.core.ad_kerberos_keys.GssKerberosKey]
 |  
 |  get_user_keytab_file_bytes_for_computer(self) -> bytes
 |      Get the raw bytes that would comprise a server keytab file for this computer. The
 |      resultant bytes form a file that can be used to initiate GSS security contexts as the
 |      computer with the computer's user principal name being the sAMAccountName.
 |  
 |  get_user_principal_name(self) -> str
 |      Gets the user principal name for the computer, to be used in initiating GSS security contexts
 |  
 |  set_encryption_types_locally(self, encryption_types: List[ms_active_directory.environment.security.security_config_constants.ADEncryptionType])
 |      Sets the encryption types of the computer locally. This will generate new kerberos keys
 |      for the computer as a user and for all of the computer's service principal names using the
 |      new encryption type.
 |      This function raises an exception if the computer's password is not set, as the password is
 |      needed to generate new kerberos keys.
 |      :param encryption_types: The list of AD encryption types to set on the computer.
 |  
 |  set_password_locally(self, password: str)
 |      Sets the password on the AD computer locally. This will regenerate server and user kerberos
 |      keys for all of the encryption types on the computer.
 |      This function is meant to be used when the password was not set locally or was incorrectly set.
 |      This function WILL NOT update the key version number of the kerberos keys; if a computer's
 |      password is actually changed, then update_password_locally should be used as that will update
 |      the key version number properly and ensure the resultant kerberos keys can be properly used
 |      for initiating and accepting security contexts.
 |      :param password: The string password to set for the computer.
 |  
 |  set_service_principal_names_locally(self, service_principal_names: List[str])
 |      Sets the service principal names for the computer, and regenerates new server kerberos keys
 |      for all of the newly set service principal names.
 |      :param service_principal_names: A list of string service principal names to set for the computer.
 |  
 |  update_password_locally(self, password: str)
 |      Update the password for the computer locally and generate new kerberos keys for the new
 |      password.
 |      :param password: The string password to set for the computer.
 |  
 |  write_full_keytab_file_for_computer(self, file_path: str, merge_with_existing_file: bool = True)
 |      Write all of the keytabs for this computer to a file, regardless of whether they represent keys for
 |      the computer to authenticate with other servers as a client, or keys to authenticate clients when acting
 |      as a server.
 |      
 |      :param file_path: The path to the file where the keytabs will be written. If it does not exist, it will be
 |                        created.
 |      :param merge_with_existing_file: If True, the computers keytabs will be added into the keytab file at
 |                                       `file_path` if one exists. If False, the file at `file_path` will be
 |                                       overwritten if it exists. If the file does not exist, this does nothing.
 |                                       Defaults to True.
 |  
 |  write_server_keytab_file_for_computer(self, file_path: str, merge_with_existing_file: bool = True)
 |      Write all of the server keytabs for this computer to a file, which are the keys used to authenticate
 |      clients when acting as a server.
 |      
 |      :param file_path: The path to the file where the keytabs will be written. If it does not exist, it will be
 |                        created.
 |      :param merge_with_existing_file: If True, the computers keytabs will be added into the keytab file at
 |                                       `file_path` if one exists. If False, the file at `file_path` will be
 |                                       overwritten if it exists. If the file does not exist, this does nothing.
 |                                       Defaults to True.
 |  
 |  write_user_keytab_file_for_computer(self, file_path: str, merge_with_existing_file: bool = True)
 |      Write all of the user keytabs for this computer to a file, which are the keys used to authenticate
 |      with other servers when acting as a client.
 |      
 |      :param file_path: The path to the file where the keytabs will be written. If it does not exist, it will be
 |                        created.
 |      :param merge_with_existing_file: If True, the computers keytabs will be added into the keytab file at
 |                                       `file_path` if one exists. If False, the file at `file_path` will be
 |                                       overwritten if it exists. If the file does not exist, this does nothing.
 |                                       Defaults to True.
 |  
 |  ----------------------------------------------------------------------
 |  Methods inherited from ManagedADObject:
 |  
 |  get_domain(self) -> 'ADDomain'
 |  
 |  get_domain_dns_name(self) -> str
 |  
 |  get_samaccount_name(self) -> str
 |  
 |  ----------------------------------------------------------------------
 |  Data descriptors inherited from ManagedADObject:
 |  
 |  __dict__
 |      dictionary for instance variables (if defined)
 |  
 |  __weakref__
 |      list of weak references to the object (if defined)

