// Fixed: CWE-639 Authorization Bypass Through User-Controlled Key (IDOR).
// The query now scopes the account lookup to the authenticated session's
// own user id, so a caller can no longer view another user's account by
// changing the accountId parameter.
package com.example.app.accounts;

import javax.servlet.http.*;
import java.sql.*;

public class AccountDetailsServlet extends HttpServlet {

    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, java.io.IOException {

        String accountId = request.getParameter("accountId");
        HttpSession session = request.getSession(false);
        if (session == null || session.getAttribute("userId") == null) {
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED);
            return;
        }
        String ownerId = (String) session.getAttribute("userId");

        try (Connection conn = DriverManager.getConnection(
                "jdbc:postgresql://localhost:5432/bank",
                System.getenv("DB_USER"), System.getenv("DB_PASSWORD"))) {

            PreparedStatement stmt = conn.prepareStatement(
                    "SELECT balance, owner_name, ssn FROM accounts WHERE id = ? AND owner_id = ?");
            stmt.setString(1, accountId);
            stmt.setString(2, ownerId);
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
