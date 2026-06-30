// CWE-330: Use of Insufficiently Random Values
// Vulnerable: java.util.Random (not cryptographically secure) used to generate
// password reset tokens and session identifiers.
package com.example.app.security;

import java.util.Random;

public class TokenGenerator {

    private static final Random random = new Random();

    public String generatePasswordResetToken() {
        // VULNERABLE: java.util.Random is seeded predictably and is not
        // suitable for security tokens; outputs can be brute-forced.
        StringBuilder token = new StringBuilder();
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        for (int i = 0; i < 16; i++) {
            token.append(chars.charAt(random.nextInt(chars.length())));
        }
        return token.toString();
    }

    public long generateSessionId() {
        // VULNERABLE: predictable session identifier
        return random.nextLong();
    }
}
