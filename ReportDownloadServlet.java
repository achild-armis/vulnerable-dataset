// CWE-22: Path Traversal
// Vulnerable: filename from the request is used directly to construct a File path.
package com.example.app.files;

import java.io.*;
import javax.servlet.http.*;

public class ReportDownloadServlet extends HttpServlet {

    private static final String REPORTS_DIR = "/var/app/reports/";

    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        String filename = request.getParameter("file");

        // VULNERABLE: no normalization or allowlist check; "../../etc/passwd" works
        File file = new File(REPORTS_DIR + filename);

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
