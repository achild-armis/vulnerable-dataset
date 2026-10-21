// CWE-79: Cross-Site Scripting (XSS)
// Vulnerable: user input rendered into the DOM without sanitization,
// and merged into an object without prototype-pollution protection.
const express = require("express");
const app = express();

app.use(express.json());

// FIXED: HTML-escape helper so untrusted values can be safely interpolated
// into HTML output.
function escapeHtml(value) {
    return String(value)
        .replace(/&/g, "&amp;")
        .replace(/</g, "&lt;")
        .replace(/>/g, "&gt;")
        .replace(/"/g, "&quot;")
        .replace(/'/g, "&#39;");
}

app.get("/profile", (req, res) => {
    const displayName = req.query.name;
    // FIXED: user input is HTML-escaped before being written into the response.
    res.send(`
        <html>
          <body>
            <h1>Welcome, ${escapeHtml(displayName)}!</h1>
          </body>
        </html>
    `);
});

// Keys that must never be copied during a merge, since they can pollute
// Object.prototype or a constructor.
const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"]);

function mergeSettings(defaults, userSettings) {
    // FIXED: reject dangerous keys so a crafted "__proto__" payload cannot
    // pollute Object.prototype.
    for (const key of Object.keys(userSettings)) {
        if (FORBIDDEN_KEYS.has(key)) {
            continue;
        }
        if (typeof userSettings[key] === "object" && userSettings[key] !== null) {
            defaults[key] = defaults[key] || {};
            mergeSettings(defaults[key], userSettings[key]);
        } else {
            defaults[key] = userSettings[key];
        }
    }
    return defaults;
}

app.post("/settings", (req, res) => {
    const finalSettings = mergeSettings({ theme: "light" }, req.body);
    res.json(finalSettings);
});

app.listen(3000);
