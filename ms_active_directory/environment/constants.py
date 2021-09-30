""" Constants describing AD Domains that aren't specific to any protocol """
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

import enum


class ADVersion(enum.Enum):
    """ This enum maps AD version friendly names to schema versions """
    WINDOWS_UNRECOGNIZED = None
    WINDOWS_2000 = 13
    # Active Directory application mode shares a schema with 2003
    WINDOWS_2003_OR_ADAM = 30
    # Active Directory lightweight directory services shares a schema with 2003R2
    WINDOWS_2003R2_OR_AD_LDS = 31
    WINDOWS_2008 = 44
    WINDOWS_2008R2 = 47
    WINDOWS_2012 = 56
    WINDOWS_2012R2 = 69
    WINDOWS_2016 = 87
    WINDOWS_2019 = 88

    @classmethod
    def get_version_from_schema_number(cls, schema):
        for ver in ADVersion:
            if ver.value == schema:
                return ver
        return ADVersion.WINDOWS_UNRECOGNIZED


class ADFunctionalLevel(enum.Enum):
    """ This enum maps AD Domain functional level friendly names to values """
    WINDOWS_UNRECOGNIZED = None
    WINDOWS_2000 = 0
    WINDOWS_2003 = 2
    WINDOWS_2008 = 3
    WINDOWS_2008R2 = 4
    WINDOWS_2012 = 5
    WINDOWS_2012R2 = 6
    WINDOWS_2016 = 7

    @classmethod
    def get_functional_level_from_value(cls, val):
        for ver in ADFunctionalLevel:
            if ver.value == val:
                return ver
        return ADFunctionalLevel.WINDOWS_UNRECOGNIZED
