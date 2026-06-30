// CWE-502: Deserialization of Untrusted Data
// Vulnerable: ObjectInputStream.readObject() called on attacker-controlled bytes.
package com.example.app.session;

import java.io.*;
import java.util.Base64;

public class SessionTokenHandler {

    public Object restoreSession(String base64Token) throws IOException, ClassNotFoundException {
        byte[] data = Base64.getDecoder().decode(base64Token);
        // VULNERABLE: deserializing untrusted input can lead to remote code execution
        // via gadget chains in libraries on the classpath (e.g. Commons Collections).
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return ois.readObject();
        }
    }

    public Object loadCachedPreferences(byte[] rawBytes) throws IOException, ClassNotFoundException {
        // VULNERABLE: same sink, fed from a cache populated by client-supplied data
        ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(rawBytes));
        return ois.readObject();
    }
}
