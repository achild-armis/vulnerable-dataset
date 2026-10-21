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

        // FIX (CWE-90): escape LDAP filter metacharacters in the untrusted
        // value before embedding it in the filter string (RFC 4515).
        String filter = "(&(objectClass=person)(uid=" + escapeLdapFilter(username) + "))";

        SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);

        return ctx.search("ou=users,dc=company,dc=com", filter, controls);
    }

    // FIX (CWE-90): escapes \, *, (, ), and NUL per RFC 4515 so untrusted
    // input cannot alter the structure of the LDAP search filter.
    private String escapeLdapFilter(String input) {
        if (input == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < input.length(); i++) {
            char c = input.charAt(i);
            switch (c) {
                case '\\':
                    sb.append("\\5c");
                    break;
                case '*':
                    sb.append("\\2a");
                    break;
                case '(':
                    sb.append("\\28");
                    break;
                case ')':
                    sb.append("\\29");
                    break;
                case '\u0000':
                    sb.append("\\00");
                    break;
                default:
                    sb.append(c);
            }
        }
        return sb.toString();
    }
}
