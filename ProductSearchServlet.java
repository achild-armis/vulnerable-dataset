// CWE-89: SQL Injection
// Vulnerable: Statement built via string concatenation with user input.
package com.example.app.controller;

import java.sql.*;
import javax.servlet.http.*;

public class ProductSearchServlet extends HttpServlet {

    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, java.io.IOException {
        String category = request.getParameter("category");

        try (Connection conn = DriverManager.getConnection(
                "jdbc:postgresql://localhost:5432/store",
                System.getenv("DB_USER"), System.getenv("DB_PASSWORD"))) {

            // FIXED: parameterized query instead of string concatenation
            PreparedStatement stmt = conn.prepareStatement(
                    "SELECT id, name, price FROM products WHERE category = ?");
            stmt.setString(1, category);
            ResultSet rs = stmt.executeQuery();

            StringBuilder out = new StringBuilder();
            while (rs.next()) {
                out.append(rs.getString("name")).append(" - $").append(rs.getDouble("price")).append("\n");
            }
            response.getWriter().write(out.toString());
        } catch (SQLException e) {
            throw new ServletException(e);
        }
    }
}
