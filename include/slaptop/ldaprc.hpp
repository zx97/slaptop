#pragma once

#include <string>
#include <vector>

namespace slaptop {

/// One `KEY value` line of an ldaprc file.
struct LdapRcEntry {
    std::string key;
    std::string value;
};

/// One ldaprc file libldap would read.
struct LdapRcFile {
    std::string path;
    std::vector<LdapRcEntry> entries;
};

/// The ldaprc files that exist, in the order libldap reads them:
/// `$LDAPRC`, `./ldaprc`, `./.ldaprc`, `$HOME/ldaprc`, `$HOME/.ldaprc`.
///
/// libldap applies these by itself when the connection is opened, which is
/// exactly why they must be *reported*: an unexpected `TLS_CACERT` or
/// `SASL_MECH` there explains a refused bind that the command line does not.
/// `LDAPNOINIT` set to anything disables the whole set, and this returns
/// nothing.
std::vector<LdapRcFile> readLdapRcFiles();

/// "BINDDN, TLS_CACERT, SASL_MECH" — the keys a file sets, for one log line.
std::string ldapRcKeys(const LdapRcFile& file);

}  // namespace slaptop
