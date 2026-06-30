// CWE-90: LDAP Injection
// Vulnerable: user input concatenated directly into an LDAP search filter.
package com.example.app.auth;

import javax.naming.NamingEnumeration;
import javax.naming.directory.*;
import java.util.Hashtable;

public class LdapUserLookup {

    public NamingEnumeration<SearchResult> findUser(String username) throws Exception {
        Hashtable<String, String> env = new Hashtable<>();
        env.put("java.naming.factory.initial", "com.sun.jndi.ldap.LdapCtxFactory");
        env.put("java.naming.provider.url", "ldap://directory.internal.company.com:389");

        DirContext ctx = new InitialDirContext(env);

        // VULNERABLE: username is concatenated directly into the filter string,
        // allowing filter injection like "*)(uid=*))(|(uid=*"
        String filter = "(&(objectClass=person)(uid=" + username + "))";

        SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);

        return ctx.search("ou=users,dc=company,dc=com", filter, controls);
    }
}
