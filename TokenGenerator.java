// CWE-330: Use of Insufficiently Random Values
// Vulnerable: java.util.Random (not cryptographically secure) used to generate
// password reset tokens and session identifiers.
package com.example.app.security;

import java.security.SecureRandom;

public class TokenGenerator {

    private static final SecureRandom random = new SecureRandom();

    public String generatePasswordResetToken() {
        // FIXED: SecureRandom is cryptographically strong and not
        // predictable, unlike java.util.Random.
        StringBuilder token = new StringBuilder();
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        for (int i = 0; i < 16; i++) {
            token.append(chars.charAt(random.nextInt(chars.length())));
        }
        return token.toString();
    }

    public long generateSessionId() {
        // FIXED: SecureRandom produces a non-predictable session identifier
        return random.nextLong();
    }
}
