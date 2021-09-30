""" Constants related to Active Directory Trust relationships """
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

# trust-related values
# trust type indicates what type of domain is being trusted.
# see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/36565693-b5e4-4f37-b0a8-c1b12138e18e
TRUST_TYPE_NON_AD_WINDOWS = 1
TRUST_TYPE_WINDOWS_AD = 2
TRUST_TYPE_MIT = 3

# trust attributes is a bitstring that indicates information around trust transitivity and such
# see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/e9a2d23c-c31e-4a6f-88a0-6646fdb51a3c
TRUST_ATTRIBUTE_NON_TRANSITIVE_BIT = 1
TRUST_ATTRIBUTE_WIN_2000_PLUS_ONLY_BIT = 2
TRUST_ATTRIBUTE_QUARANTINED_DOMAIN_BIT = 4  # set if SID filtering is used on trust
TRUST_ATTRIBUTE_FOREST_TRANSITIVE_BIT = 8  # transitive cross-forest trusts
TRUST_ATTRIBUTE_CROSS_ORGANIZATION_BIT = 16  # cross-organization trusts
TRUST_ATTRIBUTE_WITHIN_FOREST = 32  # domain in the same forest is implicitly trusted
TRUST_ATTRIBUTE_TREAT_AS_EXTERNAL = 64  # set to treat cross-forest trusts as external trusts for SID filtering
TRUST_ATTRIBUTE_USES_RC4_ENCRYPTION = 128  # used to indicate when an MIT-type trust uses RC4-HMAC. irrelevant for AD
# there are a few more attributes, but they're not relevant to clients as they concern delegation of tickets

# trust direction tells us whether we can traverse from one domain to another, or whether only incoming
# users from the other domain are accepted.
# see: https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/5026a939-44ba-47b2-99cf-386a9e674b04
TRUST_DIRECTION_DISABLED = 0
# inbound means that the trusted domain trusts the primary domain where it was found
TRUST_DIRECTION_INBOUND = 1
# outbound means that the primary domain, which is where the trusted domain was found, trusts the trusted domain
TRUST_DIRECTION_OUTBOUND = 2
TRUST_DIRECTION_BIDIRECTIONAL = 3
