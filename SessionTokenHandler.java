// CWE-502: Deserialization of Untrusted Data
// FIXED: ObjectInputStream.readObject() is never safe on untrusted/client-supplied bytes,
// since it can trigger remote code execution via gadget chains in libraries on the
// classpath. The token only ever carries simple key/value session data, so native Java
// deserialization is replaced entirely with manual, safe parsing of a delimited format.
package com.example.app.session;

import java.io.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

public class SessionTokenHandler {

    public Object restoreSession(String base64Token) throws IOException {
        byte[] data = Base64.getDecoder().decode(base64Token);
        return parseKeyValuePayload(data);
    }

    public Object loadCachedPreferences(byte[] rawBytes) throws IOException {
        return parseKeyValuePayload(rawBytes);
    }

    // Safely parses a simple "key1=value1;key2=value2" payload without ever
    // instantiating arbitrary classes from untrusted bytes.
    private Map<String, String> parseKeyValuePayload(byte[] data) throws IOException {
        String text = new String(data, "UTF-8");
        Map<String, String> fields = new HashMap<>();
        for (String entry : text.split(";")) {
            if (entry.isEmpty()) {
                continue;
            }
            int eq = entry.indexOf('=');
            if (eq < 0) {
                continue;
            }
            fields.put(entry.substring(0, eq), entry.substring(eq + 1));
        }
        return fields;
    }
}
