""" Constants for discovering and interacting with an AD domain and the environment around it """

LDAP_DNS_SRV_FORMAT = '_ldap._tcp.dc._msdcs.{domain}'
KERBEROS_DNS_SRV_FORMAT = '_kerberos._tcp.dc._msdcs.{domain}'

LDAP_SITE_AWARE_DNS_SRV_FORMAT = '_ldap._tcp.{site}._sites.dc._msdcs.{domain}'
KERBEROS_SITE_AWARE_DNS_SRV_FORMAT = '_ldap._tcp.{site}._sites.dc._msdcs.{domain}'

DNS_TIMEOUT_SECONDS = 10
