// Fixed: CWE-611 XML External Entity (XXE) Injection.
// External entity and DTD resolution are now disabled on the factory.
package com.example.app.parser;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import org.w3c.dom.Document;
import java.io.InputStream;

public class InvoiceXmlParser {

    public Document parseInvoice(InputStream xmlStream) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setXIncludeAware(false);
        factory.setExpandEntityReferences(false);
        DocumentBuilder builder = factory.newDocumentBuilder();
        Document doc = builder.parse(xmlStream);
        return doc;
    }

    public String extractInvoiceNumber(InputStream xmlStream) throws Exception {
        Document doc = parseInvoice(xmlStream);
        return doc.getElementsByTagName("invoiceNumber").item(0).getTextContent();
    }
}
