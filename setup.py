#!/usr/bin/env python3

from setuptools import setup

version = '1.10.1'
author = 'Azaria Zornberg'
email = 'a.zornberg96@gmail.com'
license_str = 'MIT License'
url = 'https://github.com/zorn96/ms_active_directory/'
description = 'Python library for integrating with Microsoft Active Directory'
package_name = 'ms_active_directory'
package_folder = '.'

long_description = open('README.md', encoding='utf-8').read()
packages = ['ms_active_directory',
            'ms_active_directory.core',
            'ms_active_directory.environment',
            'ms_active_directory.environment.discovery',
            'ms_active_directory.environment.kerberos',
            'ms_active_directory.environment.ldap',
            'ms_active_directory.environment.security'
            ]


setup_kwargs = {
    'packages': packages,
    'package_dir': {'': package_folder},
}

requirements = ['dnspython>=2.1.0',
                'ldap3>=2.8.0',
                'pyasn1>=0.4.6',
                'pycryptodome>=3.9.0',
                'pytz',
                'six>=1.15.0',
                ]

setup(name=package_name,
      version=version,
      install_requires=requirements,
      license=license_str,
      author=author,
      author_email=email,
      description=description,
      long_description=long_description,
      long_description_content_type='text/markdown',
      keywords='python3 ldap microsoft windows active-directory kerberos ad',
      python_requires=">=3.5",
      url=url,
      classifiers=['Development Status :: 5 - Production/Stable',
                   'Intended Audience :: Developers',
                   'Intended Audience :: Information Technology',
                   'Intended Audience :: System Administrators',
                   'License :: OSI Approved :: MIT License',
                   'Operating System :: MacOS :: MacOS X',
                   'Operating System :: Microsoft :: Windows',
                   'Operating System :: POSIX :: Linux',
                   'Programming Language :: Python',
                   'Programming Language :: Python :: 3',
                   'Programming Language :: Python :: 3.5',
                   'Programming Language :: Python :: 3.6',
                   'Programming Language :: Python :: 3.7',
                   'Programming Language :: Python :: 3.8',
                   'Programming Language :: Python :: 3.9',
                   'Topic :: Security',
                   'Topic :: Software Development :: Libraries :: Python Modules',
                   'Topic :: System :: Systems Administration :: Authentication/Directory :: LDAP'],
      **setup_kwargs
      )
