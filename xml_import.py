# Fixed: CWE-611 XML External Entity (XXE) Injection.
# Both parse entry points now use a parser with entity resolution, DTD
# loading, and network access disabled.
from lxml import etree
from flask import Flask, request, abort

app = Flask(__name__)

MAX_XML_BYTES = 1024 * 1024

_SAFE_PARSER = etree.XMLParser(
    resolve_entities=False, no_network=True, dtd_validation=False, load_dtd=False,
    huge_tree=False,
)


@app.route("/import/xml", methods=["POST"])
def import_xml():
    if request.content_length is not None and request.content_length > MAX_XML_BYTES:
        abort(413, description="Payload too large")
    xml_data = request.get_data()
    if len(xml_data) > MAX_XML_BYTES:
        abort(413, description="Payload too large")
    tree = etree.fromstring(xml_data, parser=_SAFE_PARSER)
    name = tree.findtext("name")
    return {"imported_name": name}


@app.route("/orders/upload", methods=["POST"])
def upload_order_xml():
    raw = request.files["order"].read(MAX_XML_BYTES + 1)
    if len(raw) > MAX_XML_BYTES:
        abort(400, description="File too large")
    doc = etree.fromstring(raw, parser=_SAFE_PARSER)
    return {"root_tag": doc.tag}


if __name__ == "__main__":
    app.run()
