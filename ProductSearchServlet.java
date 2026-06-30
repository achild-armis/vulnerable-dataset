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
                "jdbc:postgresql://localhost:5432/store", "app_user", "app_pass")) {

            Statement stmt = conn.createStatement();
            // VULNERABLE: string concatenation builds the SQL query
            String sql = "SELECT id, name, price FROM products WHERE category = '" + category + "'";
            ResultSet rs = stmt.executeQuery(sql);

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
