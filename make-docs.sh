#!/bin/bash

set -e

echo 'Removing old docs'
rm -rf docs/*

echo 'Generating docs files for top-level exported functions and objects'
python -c 'from ms_active_directory import *; help(ADDomain)' > docs/ADDomain.rst
python -c 'from ms_active_directory import *; help(ADTrustedDomain)' > docs/ADTrustedDomain.rst
python -c 'from ms_active_directory import *; help(join_ad_domain)' > docs/join_ad_domain.rst
python -c 'from ms_active_directory import *; help(join_ad_domain_by_taking_over_existing_computer)' > docs/join_ad_domain_by_taking_over_existing_computer.rst
python -c 'from ms_active_directory import *; help(join_ad_domain_using_session)' > docs/join_ad_domain_using_session.rst
python -c 'from ms_active_directory import *; help(join_ad_domain_by_taking_over_existing_computer_using_session)' > docs/join_ad_domain_by_taking_over_existing_computer_using_session.rst

python -c 'from ms_active_directory import *; help(ADSession)' > docs/ADSession.rst
python -c 'from ms_active_directory import *; help(ManagedADComputer)' > docs/ManagedADComputer.rst
python -c 'from ms_active_directory import *; help(ADSession)' > docs/ADSession.rst

python -c 'from ms_active_directory import *; help(GssKerberosKey)' > docs/GssKerberosKey.rst
python -c 'from ms_active_directory import *; help(RawKerberosKey)' > docs/RawKerberosKey.rst
python -c 'from ms_active_directory import *; help(ad_password_string_to_key)' > docs/ad_password_string_to_key.rst
python -c 'from ms_active_directory import *; help(password_string_to_key)' > docs/password_string_to_key.rst

echo 'Generating docs for exceptions'
python -c 'import ms_active_directory.exceptions; help(ms_active_directory.exceptions)' > docs/exceptions.rst

