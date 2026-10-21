// Fixed: CWE-22 Path Traversal.
// The requested filename is resolved and canonicalized, then verified to
// stay within REPORTS_DIR before it is opened.
package com.example.app.files;

import java.io.*;
import javax.servlet.http.*;

public class ReportDownloadServlet extends HttpServlet {

    private static final String REPORTS_DIR = "/var/app/reports/";

    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String filename = request.getParameter("file");

        File reportsDir = new File(REPORTS_DIR).getCanonicalFile();
        File file = new File(reportsDir, filename).getCanonicalFile();
        if (!file.toPath().startsWith(reportsDir.toPath())) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN);
            return;
        }

        try (FileInputStream fis = new FileInputStream(file);
             OutputStream out = response.getOutputStream()) {
            byte[] buffer = new byte[4096];
            int read;
            while ((read = fis.read(buffer)) != -1) {
                out.write(buffer, 0, read);
            }
        }
    }
}
