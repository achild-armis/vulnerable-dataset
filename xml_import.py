# CWE-611: Improper Restriction of XML External Entity Reference (XXE)
# Vulnerable: XML parser configured without disabling external entity resolution.
from lxml import etree
from flask import Flask, request

app = Flask(__name__)


@app.route("/import/xml", methods=["POST"])
def import_xml():
    xml_data = request.get_data()
    # VULNERABLE: resolve_entities=True (default) allows XXE payloads to read
    # local files or trigger SSRF via <!ENTITY xxe SYSTEM "...">
    parser = etree.XMLParser(resolve_entities=True)
    tree = etree.fromstring(xml_data, parser=parser)
    name = tree.findtext("name")
    return {"imported_name": name}


@app.route("/orders/upload", methods=["POST"])
def upload_order_xml():
    raw = request.files["order"].read()
    # VULNERABLE: default parser settings, no DTD/entity restrictions
    doc = etree.fromstring(raw)
    return {"root_tag": doc.tag}


if __name__ == "__main__":
    app.run(debug=True)
