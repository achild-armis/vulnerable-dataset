// Fixed: CWE-330 / CWE-338 Use of Insufficiently Random Values.
// java.util.Random is not cryptographically secure; tokens and session
// identifiers now use java.security.SecureRandom.
package com.example.app.security;

import java.security.SecureRandom;

public class TokenGenerator {

    private static final SecureRandom random = new SecureRandom();

    public String generatePasswordResetToken() {
        StringBuilder token = new StringBuilder();
        String chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        for (int i = 0; i < 16; i++) {
            token.append(chars.charAt(random.nextInt(chars.length())));
        }
        return token.toString();
    }

    public long generateSessionId() {
        return random.nextLong();
    }
}
