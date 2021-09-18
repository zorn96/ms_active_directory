""" Constants for discovering and interacting with an AD domain and the environment around it """
# Created in August 2021
#
# Author: Azaria Zornberg
#
# Copyright 2021 - 2021 Azaria Zornberg
#
# This file is part of ms_active_directory
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

LDAP_DNS_SRV_FORMAT = '_ldap._tcp.dc._msdcs.{domain}'
KERBEROS_DNS_SRV_FORMAT = '_kerberos._tcp.dc._msdcs.{domain}'

LDAP_SITE_AWARE_DNS_SRV_FORMAT = '_ldap._tcp.{site}._sites.dc._msdcs.{domain}'
KERBEROS_SITE_AWARE_DNS_SRV_FORMAT = '_ldap._tcp.{site}._sites.dc._msdcs.{domain}'

DNS_TIMEOUT_SECONDS = 10
