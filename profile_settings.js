// CWE-79: Cross-Site Scripting (XSS)
// Vulnerable: user input rendered into the DOM without sanitization,
// and merged into an object without prototype-pollution protection.
const express = require("express");
const app = express();

app.use(express.json());

app.get("/profile", (req, res) => {
    const displayName = req.query.name;
    // VULNERABLE: unsanitized user input written directly into HTML response
    res.send(`
        <html>
          <body>
            <h1>Welcome, ${displayName}!</h1>
          </body>
        </html>
    `);
});

function mergeSettings(defaults, userSettings) {
    // VULNERABLE: naive deep merge allows "__proto__" keys to pollute
    // Object.prototype, affecting every object in the application.
    for (const key in userSettings) {
        if (typeof userSettings[key] === "object") {
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
