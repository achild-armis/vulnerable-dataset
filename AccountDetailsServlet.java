// CWE-639: Authorization Bypass Through User-Controlled Key (IDOR)
// Vulnerable: account ID taken directly from the request with no ownership check.
package com.example.app.accounts;

import javax.servlet.http.*;
import java.sql.*;

public class AccountDetailsServlet extends HttpServlet {

    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, java.io.IOException {

        String accountId = request.getParameter("accountId");

        // FIXED: bind resource access to the authenticated principal. The account must
        // belong to the logged-in user, not merely be reachable by guessing an id.
        HttpSession session = request.getSession(false);
        if (session == null || session.getAttribute("userId") == null) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }
        String currentUserId = session.getAttribute("userId").toString();

        try (Connection conn = DriverManager.getConnection(
                "jdbc:postgresql://localhost:5432/bank", "app", "app")) {

            PreparedStatement stmt = conn.prepareStatement(
                    "SELECT balance, owner_name, ssn FROM accounts WHERE id = ? AND owner_id = ?");
            stmt.setString(1, accountId);
            stmt.setString(2, currentUserId);
            ResultSet rs = stmt.executeQuery();

            if (rs.next()) {
                response.getWriter().write(
                        "Owner: " + rs.getString("owner_name") +
                        ", Balance: " + rs.getDouble("balance"));
            } else {
                response.sendError(HttpServletResponse.SC_FORBIDDEN);
            }
        } catch (SQLException e) {
            throw new ServletException(e);
        }
    }
}
