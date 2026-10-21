// CWE-798: Use of Hard-coded Credentials
// Vulnerable: database password and encryption key are hardcoded constants.
package com.example.app.config;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class DatabaseConfig {

    // FIXED: credentials loaded from environment at runtime instead of being
    // committed to source control.
    private static final String DB_URL = "jdbc:mysql://prod-db.internal:3306/orders";
    private static final String DB_USER = System.getenv("DB_USER");
    private static final String DB_PASSWORD = System.getenv("DB_PASSWORD");

    // FIXED: AES key loaded from environment instead of a static value shared
    // across every deployment.
    public static final String AES_SECRET_KEY = System.getenv("AES_SECRET_KEY");

    public static Connection getConnection() throws SQLException {
        return DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
    }
}
