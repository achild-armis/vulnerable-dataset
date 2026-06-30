// CWE-611: XML External Entity (XXE) Injection
// Vulnerable: DocumentBuilderFactory does not disable external entities/DTDs.
package com.example.app.parser;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import java.io.InputStream;

public class InvoiceXmlParser {

    public Document parseInvoice(InputStream xmlStream) throws Exception {
        // VULNERABLE: default factory settings allow external entity resolution
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        DocumentBuilder builder = factory.newDocumentBuilder();
        // An attacker-supplied XML with <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
        // can exfiltrate local files through this parser.
        Document doc = builder.parse(xmlStream);
        return doc;
    }

    public String extractInvoiceNumber(InputStream xmlStream) throws Exception {
        Document doc = parseInvoice(xmlStream);
        return doc.getElementsByTagName("invoiceNumber").item(0).getTextContent();
    }
}
