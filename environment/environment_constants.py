""" Constants for discovering and interacting with an AD domain and the environment around it """

LDAP_DNS_SRV_FORMAT = '_ldap._tcp.dc._msdcs.{domain}'
KERBEROS_DNS_SRV_FORMAT = '_kerberos._tcp.dc._msdcs.{domain}'

DNS_TIMEOUT_SECONDS = 10
