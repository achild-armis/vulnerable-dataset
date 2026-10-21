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

        // FIXED: defensively reject path separators / traversal sequences in the raw
        // filename, then resolve against the fixed base directory and verify the
        // canonical result is still contained within it before opening the file.
        if (filename == null || filename.isEmpty()
                || filename.contains("..") || filename.contains("/") || filename.contains("\\")) {
            response.sendError(HttpServletResponse.SC_BAD_REQUEST);
            return;
        }

        File baseDir = new File(REPORTS_DIR).getCanonicalFile();
        File file = new File(baseDir, filename).getCanonicalFile();

        if (!file.getPath().startsWith(baseDir.getPath() + File.separator)) {
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
