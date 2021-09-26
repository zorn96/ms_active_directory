The ms_active_directory project
###############################

``ms_active_directory`` is a library designed to make integrations with Active Directory domains, and tools for managing them,
easier to write.

There are a large number of protocols that can be used to interact with Active Directory domains, but
a lot of them can be difficult to use when designing a tool or integration from scratch. They can be confusing to use
because the protocols in most cases were not designed specifically for Microsoft Active Directory, and so there will be
behavioral quirks and slightly differences when using them with Active Directory.

The primary goal of this library is to allow users, whether they be SysAdmins, DevOps Engineers, or Software Engineers
developing a new product that integrates with Active Directory, to abstract away the need to deeply understand the
different options for integration and their quirks.

The secondary goal of this library is platform independence. There are a lot of tools for Active Directory that are
windows-only, or that behave differently on different operating systems due to using system libraries.
In order to achieve some amount of platform independence, this library works out of the box using pure python
and builds primarily on other python packages that are pure python such as ``ldap3``. However, certain optional
features (e.g. Kerberos negotiation) will require python packages that build upon system libraries; this is done
in order to avoid reimplementing complex security-related features, and to instead use well-trusted and verified
implementations of them.


License
-------

The ``ms_active_directory`` library is distributed under the MIT License.

This means that users of this library may freely use, copy, modify, merge, publish, distribute,
sublicense, and/or sell copies of the Software. The only condition is that the appropriate
copyright notice be included with any copies or substantial portions of the library.

RFCs Compliance
---------------

This library largely utilizes the LDAP protocol for communication, as well as DNS. Utilization of those
protocols is done via other python libraries. In particular, ``ldap3`` is used for LDAP communication,
and so all LDAP communication is compliant with RFCs 4510-4518.

Generation of kerberos keys for Active Directory, and parsing of kerberos keys, according to various
kerberos encryption types is done in compliance with RFC4757, RFC1964, RFC8429, RFC3962, and a variety
of other RFCs that define how kerberos keys are to be derived and encoded for different encryption types.
However, actual kerberos negotiation relies on the underlying OS mechanism that implements GSSAPI, and
so this library makes no claim to enforce specific RFC compliance in the actual negotiation, as even
different versions of the same OS have significant differences (e.g. Ubuntu 14 vs. 18).

PEP8 Compliance
---------------

``ms_active_directory`` is PEP8 compliant, excluding line length. PEP8 (https://www.python.org/dev/peps/pep-0008/) is
the standard coding style guide for the Python Standard Library and for many other Python projects. It provides a
consistent way of writing code for maintainability and readability following the principle that "software is more read
than written".

Type hints are also utilized in all outwardly exposed classes and functions implemented in the library, and nearly all
functions overall.


Home Page
---------

The home page of the ``ms_active_directory`` project is https://github.com/zorn96/ms_active_directory


Documentation
-------------

Documentation is available at https://ms-active-directory.readthedocs.io/. You can download a PDF copy of the manual at
https://media.readthedocs.org/pdf/ms-active-directory/stable/ms-active-directory.pdf

Documentation vs. Examples
--------------------------

If you're looking for examples of using the library, there's a good number of examples in the github repo's
README file and the repo itself, which help to provide concrete demonstrations of how to use the functions
documented here.

The documentation is based on the docstrings in the repo and the type annotations in the repo, which
means that it's incredibly detailed and thorough. A point of pride for this library is the complete type
annotation of functions and highly descriptive docstrings for every user-facing function.


Download
--------

The ``ms_active_directory`` package can be downloaded at https://pypi.org/project/ms-active-directory/.


Install
-------

Install with **pip install ms_active_directory**. If needed the library installs the ``pyasn1`` package, ``ldap3``,
``dnspython``, and ``pycryptodome``. There are some other packages that may be installed but they're fairly standard
(e.g. ``six``).
If you need Kerberos support you must install the ``gssapi`` package, or the ``winkerberos`` package if you're windows
in a setup where ``gssapi`` does not work. These packages may require other system libraries be installed.

GIT repository
--------------

You can download the latest released source code at https://github.com/zorn96/ms_active_directory/tree/main


Contributing to this project
----------------------------

``ms_active_directory`` source is hosted on github. You can contribute to the project on https://github.com/zorn96/ms_active_directory
forking the project and submitting a *pull request* with your modifications.


Support
-------

You can submit support tickets on https://github.com/zorn96/ms_active_directory/issues/new


Contact me
----------

For information and suggestions you can contact me at a.zornberg96@gmail.com. You can also open a support ticket on
https://github.com/zorn96/ms_active_directory/issues/new


Donate
------

If you want to keep this project up and running you can send me an Amazon gift card. I will use it to
improve my skills in the Information and Communication technologies.


Acknowledgements and Shout-outs
-------------------------------

* **Ilya Etingof**, the author of the ``pyasn1`` package for his excellent work and support.

* **Giovanni Cannata** for his work on the ``ldap3`` package, which is where I got my start on learning about this
  area, and which is an integral part of this package.

* **GitHub** for providing the *free source repository space and tools* used to develop this project.

* **VMWare** for providing the free licenses used to run windows VMs for developing and testing this library.

Documentation Contents
----------------------

.. toctree::
   :maxdepth: 2

   primary_object_index
   info_object_index
   exceptions
   join_ad_domain
   join_ad_domain_by_taking_over_existing_computer
   join_ad_domain_using_session
   join_ad_domain_by_taking_over_existing_computer_using_session
