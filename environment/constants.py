""" Constants describing AD Domains that aren't specific to any protocol """
import enum


class ADVersion(enum.Enum):
    """ This enum maps AD version friendly names to schema versions """
    WINDOWS_UNRECOGNIZED = None
    WINDOWS_2000 = 13
    WINDOWS_2003 = 30
    WINDOWS_2003R2 = 31
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
