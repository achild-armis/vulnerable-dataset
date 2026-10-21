# CWE-611: Improper Restriction of XML External Entity Reference (XXE)
# Vulnerable: XML parser configured without disabling external entity resolution.
from lxml import etree
from flask import Flask, request

app = Flask(__name__)


@app.route("/import/xml", methods=["POST"])
def import_xml():
    xml_data = request.get_data()
    # FIXED: disable entity resolution, DTD loading, and network access to
    # prevent XXE payloads from reading local files or triggering SSRF.
    parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)
    tree = etree.fromstring(xml_data, parser=parser)
    name = tree.findtext("name")
    return {"imported_name": name}


@app.route("/orders/upload", methods=["POST"])
def upload_order_xml():
    raw = request.files["order"].read()
    # FIXED: use a hardened parser with entity resolution, DTD loading, and
    # network access disabled instead of the permissive default parser.
    parser = etree.XMLParser(resolve_entities=False, no_network=True, load_dtd=False)
    doc = etree.fromstring(raw, parser=parser)
    return {"root_tag": doc.tag}


if __name__ == "__main__":
    app.run(debug=True)
