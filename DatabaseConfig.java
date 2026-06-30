// CWE-798: Use of Hard-coded Credentials
// Vulnerable: database password and encryption key are hardcoded constants.
package com.example.app.config;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

public class DatabaseConfig {

    // VULNERABLE: credentials committed directly to source control
    private static final String DB_URL = "jdbc:mysql://prod-db.internal:3306/orders";
    private static final String DB_USER = "root";
    private static final String DB_PASSWORD = "RootPass123!";

    // VULNERABLE: static AES key embedded in code, same for every deployment
    public static final String AES_SECRET_KEY = "0123456789abcdef";

    public static Connection getConnection() throws SQLException {
        return DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
    }
}
