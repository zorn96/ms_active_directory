``GssKerberosKey`` Objects
--------------------------

::

    class GssKerberosKey(builtins.object)
        GssKerberosKey(principal: str, realm: str, raw_key: ms_active_directory.core.ad_kerberos_keys.RawKerberosKey, kvno: int, flags: int = None, timestamp: int = None, gss_name_type: int = 0, format_version: int = 2)
        
        A kerberos key that can actually be used in kerberos negotiation (as either a user or a server).
        This is a raw key properly wrapped with encoded additional information about the principal, kvno,
        encryption type, etc.
        
        Methods defined here:
        
        __init__(self, principal: str, realm: str, raw_key: ms_active_directory.core.ad_kerberos_keys.RawKerberosKey, kvno: int, flags: int = None, timestamp: int = None, gss_name_type: int = 0, format_version: int = 2)
            Initialize self.  See help(type(self)) for accurate signature.
        
        get_complete_keytab_bytes(self, format_version: int = None, use_current_time: bool = None)
            Get this key object encoded as the bytes of a complete, usable keytab that can be written
            to a file and used for kerberos authentication (initiating or accepting contexts).
            :param format_version: An keytab format version. If not specified, defaults to the format version
                                   in the object. If the object's format version is null, defaults to 2.
            :param use_current_time: Whether or not the current time should be used as the timestamp in the
                                     keytab produced, overwriting the time in the object. If no timestamp is
                                     in the object, the current time is used. Defaults to False if not specified.
        
        get_raw_key_bytes(self)
        
        set_flags(self, flags: int)
            Sets the flags and clears complete_gss_keytab_bytes so we re-compute it
        
        set_format_version(self, format_version: int)
            Sets the keytab format version and clears complete_gss_keytab_bytes so we re-compute it
        
        set_gss_name_type(self, name_type: int)
            Sets the gss name type and friendly name type and clears complete_gss_keytab_bytes so we re-compute it
        
        set_kvno(self, kvno: int)
            Sets the kvno and clears complete_gss_keytab_bytes so we re-compute it
        
        set_principal(self, principal: str)
            Sets the principal and clears complete_gss_keytab_bytes so we re-compute it
        
        set_raw_key(self, raw_key: ms_active_directory.core.ad_kerberos_keys.RawKerberosKey)
            Sets the raw key, updates our encryption type and clears complete_gss_keytab_bytes so we re-compute it.
            The encryption type is directly tied to our raw key and vice versa, so setting one without the other makes no
            sense.
        
        set_realm(self, realm: str)
            Sets the realm and clears complete_gss_keytab_bytes so we re-compute it
        
        set_timestamp(self, timestamp: int)
            Sets the timestamp and clears complete_gss_keytab_bytes so we re-compute it
        
        uses_active_directory_supported_encryption_type(self)
