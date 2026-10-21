// Fixed: CWE-79 Cross-Site Scripting (XSS) and CWE-1327 Prototype
// Pollution. The display name is now HTML-escaped before being embedded
// in the response, and the settings merge rejects dangerous keys
// (__proto__, constructor, prototype) and only copies own properties.
const express = require("express");
const escapeHtml = require("escape-html");
const app = express();

app.use(express.json());

app.get("/profile", (req, res) => {
    const displayName = req.query.name;
    res.send(`
        <html>
          <body>
            <h1>Welcome, ${escapeHtml(displayName)}!</h1>
          </body>
        </html>
    `);
});

const DANGEROUS_KEYS = new Set(["__proto__", "constructor", "prototype"]);

// Merge result objects use a null prototype, so even if a dangerous key
// slipped past the filter, assigning it would create a plain own property
// instead of reaching Object.prototype.
function mergeSettings(defaults, userSettings) {
    const result = Object.create(null);
    for (const key of Object.keys(defaults || {})) {
        result[key] = defaults[key];
    }
    for (const key of Object.keys(userSettings || {})) {
        if (DANGEROUS_KEYS.has(key)) {
            continue;
        }
        const value = userSettings[key];
        if (value !== null && typeof value === "object" && !Array.isArray(value)) {
            const base = (result[key] !== null && typeof result[key] === "object") ? result[key] : {};
            result[key] = mergeSettings(base, value);
        } else {
            result[key] = value;
        }
    }
    return result;
}

app.post("/settings", (req, res) => {
    const finalSettings = mergeSettings({ theme: "light" }, req.body);
    res.json(finalSettings);
});

app.listen(3000);
