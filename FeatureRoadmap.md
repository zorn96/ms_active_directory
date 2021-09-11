#Planned Features

This file exists to help me remember the different things I want to build, and create a rough ordering.

If you'd like some functionality that isn't listed here, please open an issue and describe it.

1. Add support for recursively finding groups for users/groups. Where callers can specify a depth or just
   request exhaustive recursion, to get the full trees of members->groups. Support optional flattening of results.
2. Add support for recursively finding members of groups. Same as above.
3. Add support for discovering which optional features are enabled in a domain (e.g. the recycling bin feature,
   time-based AD group memberships).
4. Add support for creating time-based group memberships.
5. Add support for on-demand multi-domain searches. This would be a keyword argument to the various
   `find` functions for users/groups/memberships/etc. to enable traversal of cross-domain trusts.
6. Add support for automatic multi-domain searches. This would be a session setting to allow all searches
   to automatically traverse cross-domain trusts exhaustively.
7. Add support for configuring kerberos on *nix operating systems based on what's discovered about a
   domain, and based on a managed object's kerberos keys.
8. Add support for creating users and groups.
9. Add extended posix support, including accounting for posix offsets in multi-domain trust searches, and
   lookups for posix users/groups with both strict and non-strict options.
