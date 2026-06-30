// CWE-639: Authorization Bypass Through User-Controlled Key (IDOR)
// Vulnerable: account ID taken directly from the request with no ownership check.
package com.example.app.accounts;

import javax.servlet.http.*;
import java.sql.*;

public class AccountDetailsServlet extends HttpServlet {

    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, java.io.IOException {

        String accountId = request.getParameter("accountId");
        // VULNERABLE: no check that the logged-in user actually owns this accountId.
        // Any authenticated user can view any other user's account by changing the
        // accountId parameter (Insecure Direct Object Reference).
        try (Connection conn = DriverManager.getConnection(
                "jdbc:postgresql://localhost:5432/bank", "app", "app")) {

            PreparedStatement stmt = conn.prepareStatement(
                    "SELECT balance, owner_name, ssn FROM accounts WHERE id = ?");
            stmt.setString(1, accountId);
            ResultSet rs = stmt.executeQuery();

            if (rs.next()) {
                response.getWriter().write(
                        "Owner: " + rs.getString("owner_name") +
                        ", Balance: " + rs.getDouble("balance"));
            }
        } catch (SQLException e) {
            throw new ServletException(e);
        }
    }
}
