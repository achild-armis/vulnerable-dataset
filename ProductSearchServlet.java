// Fixed: CWE-89 SQL Injection (parameterized query) and CWE-798 Hard-coded
// Credentials (connection credentials now read from the environment).
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

            String sql = "SELECT id, name, price FROM products WHERE category = ?";
            PreparedStatement stmt = conn.prepareStatement(sql);
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
