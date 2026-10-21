// Fixed: CWE-90 LDAP Injection.
// The username is now escaped per RFC 4515 before being embedded in the
// search filter, neutralizing LDAP filter metacharacters.
package com.example.app.auth;

import javax.naming.NamingEnumeration;
import javax.naming.directory.*;
import java.util.Hashtable;

public class LdapUserLookup {

    private static String escapeLdapFilter(String input) {
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            switch (c) {
                case '\\': sb.append("\\5c"); break;
                case '*': sb.append("\\2a"); break;
                case '(': sb.append("\\28"); break;
                case ')': sb.append("\\29"); break;
                case '\0': sb.append("\\00"); break;
                default: sb.append(c);
            }
        }
        return sb.toString();
    }

    public NamingEnumeration<SearchResult> findUser(String username) throws Exception {
        Hashtable<String, String> env = new Hashtable<>();
        env.put("java.naming.factory.initial", "com.sun.jndi.ldap.LdapCtxFactory");
        env.put("java.naming.provider.url", "ldap://directory.internal.company.com:389");

        DirContext ctx = new InitialDirContext(env);

        String filter = "(&(objectClass=person)(uid=" + escapeLdapFilter(username) + "))";

        SearchControls controls = new SearchControls();
        controls.setSearchScope(SearchControls.SUBTREE_SCOPE);

        return ctx.search("ou=users,dc=company,dc=com", filter, controls);
    }
}
