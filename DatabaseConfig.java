// Fixed: CWE-798 Use of Hard-coded Credentials.
// Credentials and the encryption key are now read from the environment
// instead of being committed to source control.
package com.example.app.config;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class DatabaseConfig {

    private static final String DB_URL = System.getenv("DB_URL");
    private static final String DB_USER = System.getenv("DB_USER");
    private static final String DB_PASSWORD = System.getenv("DB_PASSWORD");

    public static final String AES_SECRET_KEY = System.getenv("AES_SECRET_KEY");

    public static Connection getConnection() throws SQLException {
        return DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
    }
}
