import os

from typing import List, Optional, Tuple, TYPE_CHECKING

from ms_active_directory.environment.kerberos.kerberos_constants import (
    DEFAULT_REALM_FORMAT,
    DOMAIN_REALM_MAP_FORMAT,
    KRB5_CONF_DEFAULTS_TAG,
    KRB5_CONF_DOMAIN_REALMS_TAG,
    KRB5_CONF_REALMS_TAG,
    POSIX_KRB5_CONF_LOCATION,
    REALM_ENTRY_FORMAT,
    REALM_ENTRY_COMPONENT_FORMAT,
    WINDOWS_KRB5_CONF_LOCATION_NEW,
    WINDOWS_KRB5_CONF_LOCATION_OLD,
)
from ms_active_directory.exceptions import SystemConfigurationUpdateException
from ms_active_directory.logging_utils import get_logger

if TYPE_CHECKING:
    from ms_active_directory.core.ad_domain import ADDomain

logger = get_logger()


def update_system_kerberos_configuration_for_domains(ad_domains: List['ADDomain'],
                                                     default_domain: 'ADDomain' = None,
                                                     merge_with_existing_file: bool = True,
                                                     krb5_location: str = None):
    """ Update the system's kerberos configuration files for one or more AD domains in order to enable kerberos
    authentication.

    :param ad_domains: A list of ADDomain objects representing the domains.
    :param default_domain: Optional. If specified, this domain will be configured as the default domain.
    :param merge_with_existing_file: If False, overwrite the kerberos configuration file instead of merging the domain's
                                     realm entries into the existing file. Defaults to True.
    :param krb5_location: The file path to the kerberos configuration to update. If not specified, defaults to
                          `/windows/krb5.ini` and `/winnt/krb5.ini` on windows systems and `/etc/krb5.conf` on others.
    :raises: SystemConfigurationUpdateException if we fail to update the configuration files.
    """
    realm_entries = []
    realms = []
    domain_realm_map_entries = []
    default_realm_entry = None
    for domain in ad_domains:
        realm = domain.get_domain_dns_name().upper()
        lower_mapped_domain = realm.lower()
        realm_components = [REALM_ENTRY_COMPONENT_FORMAT.format(server_type='kdc', address=addr)
                            for addr in domain.get_kerberos_uris()]
        realm_entry = REALM_ENTRY_FORMAT % (realm, '\n'.join(realm_components))
        mapping_entry = DOMAIN_REALM_MAP_FORMAT.format(domain=lower_mapped_domain,
                                                       realm=realm)
        realms.append(realm)
        realm_entries.append(realm_entry)
        domain_realm_map_entries.append(mapping_entry)

    if default_domain:
        default_realm_entry = DEFAULT_REALM_FORMAT.format(realm=default_domain.get_domain_dns_name().upper())

    # if the user specified the krb5 location, keep track of that. otherwise, guess based on our architecture
    user_specified_output_location = False
    if not krb5_location:
        if os.name == 'nt':
            # prefer the new location over the old one
            krb5_locations = [WINDOWS_KRB5_CONF_LOCATION_NEW, WINDOWS_KRB5_CONF_LOCATION_OLD]
        else:
            krb5_locations = [POSIX_KRB5_CONF_LOCATION]
    else:
        krb5_locations = [krb5_location]
        user_specified_output_location = True

    # get our file contents
    if not merge_with_existing_file:
        krb5_contents = _build_krb5_conf_file(realm_entries, domain_realm_map_entries, default_realm_entry)
    else:
        read_location, current_krb5_lines = _read_existing_krb5_conf_file_lines(krb5_locations)
        # if we found an existing krb5 config file, only update that location.
        # if there was no existing file, then we'll write to all of the locations where the OS could look
        if read_location is not None:
            krb5_locations = [read_location]
        # if we're setting the default realm, then drop the default realm from the current config
        if default_realm_entry:
            current_krb5_lines = [line for line in current_krb5_lines
                                  if not line.strip().startswith('default_ream')]
        krb5_contents = _combine_realms_into_current_krb5_file(current_krb5_lines, realms, realm_entries,
                                                               domain_realm_map_entries, default_realm_entry)

    # if the caller set the output location, we need to succeed in updating it or we'll raise an error.
    # but if we're guessing at where to write, we might fail to write to one location because it doesn't exist
    # as a directory (e.g. the new windows location on an old machine), so don't raise an exception unless all writes
    # fail
    any_locations_updated = False
    for location in krb5_locations:
        try:
            with open(location, 'w') as krb5_fp:
                krb5_fp.write(krb5_contents)
                any_locations_updated = True
            logger.info('Successfully wrote krb5 configuration to %s', location)
        except Exception as ex:
            logger.warning('Failed to update location %s with krb5 configuration. Exception %s', location, ex)
            if user_specified_output_location:
                raise SystemConfigurationUpdateException('Failed to update krb5 configuration file at {}'
                                                         .format(location))
    if not any_locations_updated:
        raise SystemConfigurationUpdateException('Failed to update any krb5 configuration files after attempting to '
                                                 'write to the following locations {}'
                                                 .format(', '.join(krb5_locations)))


def _build_krb5_conf_file(realm_entries: List[str], domain_realm_map_entries: List[str],
                          default_realm_entry: str = None) -> str:
    """ Create a krb5.conf file given the default realm (if any) and the entries for the realms and their domain
    mappingsg
    """
    prefix = ''
    if default_realm_entry:
        prefix = KRB5_CONF_DEFAULTS_TAG + '\n' + default_realm_entry

    realms = KRB5_CONF_REALMS_TAG + '\n' + '\n'.join(realm_entries)
    domain_mappings = KRB5_CONF_DOMAIN_REALMS_TAG + '\n' + '\n'.join(domain_realm_map_entries)
    return '\n'.join([prefix, realms, domain_mappings])


def _read_existing_krb5_conf_file_lines(locations: List[str]) -> Tuple[Optional[str], List[str]]:
    """ Read in existing krb5 configuration file lines and return them """
    for loc in locations:
        if os.path.isfile(loc):
            with open(loc) as fp:
                krb5_lines = fp.readlines()
                # be careful of empty files
                if krb5_lines:
                    return loc, krb5_lines
    return None, []


def _combine_realms_into_current_krb5_file(current_krb5_lines: List[str], realms: List[str], realm_entries: List[str],
                                           domain_realm_map_entries: List[str],
                                           default_realm_entry: str = None) -> str:
    """ Merge realm entries and domain->realm mappings into an existing krb5 configuration file's contents.
    If the realms we have entries for are already existing in the configuration file, they're removed and replaced.
    """
    final_lines = []
    realm_inserts = '\n'.join(realm_entries)
    realms_inserted = False
    domain_mapping_inserts = '\n'.join(domain_realm_map_entries)
    domain_mappings_inserted = False
    default_realm_inserted = True if default_realm_entry is None else False
    currently_skipping_realm = None
    for line in current_krb5_lines:
        # firstly, if we're currently skipping a realm, skip this line and end the skipping if the line is the closing
        # tag for the reaqulm
        if currently_skipping_realm and line.strip() != '}':
            print('Skipping line {line} of existing configuration for {realm} because we are overwriting it.'
                        .format(line=line, realm=currently_skipping_realm))
            continue
        if currently_skipping_realm and line.strip() == '}':
            currently_skipping_realm = None
            print('Final line of configuration for {realm} seen. Done skipping {realm}'
                        .format(realm=currently_skipping_realm))
            continue

        # if we're not actively skipping a realm's configuration, check if we should start
        line_pieces = [piece.strip() for piece in line.split('=')]
        if line_pieces[0] in realms and line_pieces[1] == '{':
            currently_skipping_realm = line_pieces[0]
            print('Starting to skip realm {realm} in existing configuration because we are overwriting it.'
                        .format(realm=currently_skipping_realm))
            continue

        final_lines.append(line)
        # if we've reached the krb5 defaults, and have a default realm entry, insert it
        if line.strip() == KRB5_CONF_DEFAULTS_TAG and default_realm_entry:
            final_lines.append(default_realm_entry)
            default_realm_inserted = True
        # if we've reached the realm definitions, insert our realms
        if line.strip() == KRB5_CONF_REALMS_TAG:
            final_lines.append(realm_inserts)
            realms_inserted = True
        # if we've reached the domain mapping definitions, insert our domains
        if line.strip() == KRB5_CONF_DOMAIN_REALMS_TAG:
            final_lines.append(domain_mapping_inserts)
            domain_mappings_inserted = True

    # if we didn't insert something, it means that the existing file didn't define it, so we add new sections as needed
    if not default_realm_inserted:
        final_lines.append(KRB5_CONF_DEFAULTS_TAG)
        final_lines.append(default_realm_entry)
    if not realms_inserted:
        final_lines.append(KRB5_CONF_REALMS_TAG)
        final_lines.append(realm_inserts)
    if not domain_mappings_inserted:
        final_lines.append(KRB5_CONF_DOMAIN_REALMS_TAG)
        final_lines.append(domain_mapping_inserts)

    return '\n'.join(final_lines) + '\n'
