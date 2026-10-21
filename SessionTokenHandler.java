// Fixed: CWE-502 Deserialization of Untrusted Data.
// Java object deserialization of attacker-controlled bytes is unsafe regardless
// of filtering heuristics, so untrusted session/preference payloads are now
// decoded as JSON instead of going through ObjectInputStream.
package com.example.app.session;

import java.io.*;
import java.util.Base64;
import java.util.Map;
import com.fasterxml.jackson.databind.ObjectMapper;

public class SessionTokenHandler {

    private static final int MAX_PAYLOAD_BYTES = 64 * 1024;

    private static final ObjectMapper MAPPER = new ObjectMapper();
    static {
        // Explicitly ensure polymorphic/default typing is off so the JSON
        // payload can never instruct Jackson to instantiate arbitrary classes.
        MAPPER.deactivateDefaultTyping();
    }

    public Map<String, Object> restoreSession(String base64Token) throws IOException {
        byte[] data = Base64.getDecoder().decode(base64Token);
        if (data.length > MAX_PAYLOAD_BYTES) {
            throw new IOException("Payload too large");
        }
        return MAPPER.readValue(data, Map.class);
    }

    public Map<String, Object> loadCachedPreferences(byte[] rawBytes) throws IOException {
        if (rawBytes.length > MAX_PAYLOAD_BYTES) {
            throw new IOException("Payload too large");
        }
        return MAPPER.readValue(rawBytes, Map.class);
    }
}
