.. ms_active_directory documentation master file, created by
   sphinx-quickstart on Tue Sep 21 19:49:13 2021.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

Welcome to ms_active_directory's documentation!
===============================================

``ms_active_directory`` is a pure Python client library for developing tools for and integrations with
Microsoft Active Directory domains. It is mostly platform independent, with optional features that
do have platform specific behavior.

It includes utilities for discovering and searching domains, as well as joining computers to them, modifying
entities within them, and looking up information about users, groups, computers, and other objects.

It does its best to abstract away the nuances and quirks of Active Directory, and allow users to easily
perform common operations in a highly efficient manner that is highly secure by default, while also
being flexible enough for power users to perform complex operations not supported by the library in
pre-made functions.

This library tries to conform to all Active Directory standard defaults in terms of object locations,
entity object classes, encryption types used, DNS names used for computers, etc.


Documentation vs. Examples
--------------------------

If you're looking for examples of using the library, there's a good number of examples in the github repo's
README file and the repo itself, which help to provide concrete demonstrations of how to use the functions
documented here.

The documentation here is based on the docstrings in the repo and the type annotations in the repo, which
means that it's incredibly detailed and thorough. A point of pride for this library is the complete type
annotation of functions and highly descriptive docstrings for every user-facing function.

Contents
--------

.. toctree::
   :maxdepth: 2

   welcome
   primary_object_index
   info_object_index
   exceptions
   join_ad_domain
   join_ad_domain_by_taking_over_existing_computer
   join_ad_domain_using_session
   join_ad_domain_by_taking_over_existing_computer_using_session
