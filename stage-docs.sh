#!/bin/bash

set -e

echo 'Removing old staging docs'
rm -rf docs_staging/*

echo 'Generating docs files for top-level exported functions and objects'
python -c 'from ms_active_directory import *; help(ADDomain)' > docs_staging/ADDomain.rst
python -c 'from ms_active_directory import *; help(ADTrustedDomain)' > docs_staging/ADTrustedDomain.rst
python -c 'from ms_active_directory import *; help(join_ad_domain)' > docs_staging/join_ad_domain.rst
python -c 'from ms_active_directory import *; help(join_ad_domain_by_taking_over_existing_computer)' > docs_staging/join_ad_domain_by_taking_over_existing_computer.rst
python -c 'from ms_active_directory import *; help(join_ad_domain_using_session)' > docs_staging/join_ad_domain_using_session.rst
python -c 'from ms_active_directory import *; help(join_ad_domain_by_taking_over_existing_computer_using_session)' > docs_staging/join_ad_domain_by_taking_over_existing_computer_using_session.rst

python -c 'from ms_active_directory import *; help(ADSession)' > docs_staging/ADSession.rst
python -c 'from ms_active_directory import *; help(ManagedADComputer)' > docs_staging/ManagedADComputer.rst
python -c 'from ms_active_directory import *; help(ADSession)' > docs_staging/ADSession.rst

python -c 'from ms_active_directory import *; help(GssKerberosKey)' > docs_staging/GssKerberosKey.rst
python -c 'from ms_active_directory import *; help(RawKerberosKey)' > docs_staging/RawKerberosKey.rst
python -c 'from ms_active_directory import *; help(ad_password_string_to_key)' > docs_staging/ad_password_string_to_key.rst
python -c 'from ms_active_directory import *; help(password_string_to_key)' > docs_staging/password_string_to_key.rst

echo 'Generating docs for exceptions'
python -c 'import ms_active_directory.exceptions; help(ms_active_directory.exceptions)' > docs_staging/exceptions.rst

