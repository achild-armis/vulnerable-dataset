// CWE-611: XML External Entity (XXE) Injection
// CWE-502: Deserialization of Untrusted Data
// Vulnerable: Groovy script parses attacker-supplied XML with default,
// unsafe parser settings, and deserializes an untrusted object stream
// (a pattern frequently seen in Jenkins pipeline / Grails utility scripts).
import groovy.xml.XmlSlurper

// FIX (CWE-502): restrict deserialization to a strict class allow-list so
// attacker-controlled bytes cannot instantiate arbitrary gadget-chain classes.
class SafeObjectInputStream extends ObjectInputStream {

    private static final Set<String> ALLOWED_CLASSES = [
        'java.lang.String',
        'java.lang.Integer',
        'java.lang.Long',
        'java.lang.Boolean',
        'java.util.HashMap',
        'java.util.ArrayList'
    ] as Set

    SafeObjectInputStream(InputStream in) {
        super(in)
    }

    @Override
    protected Class<?> resolveClass(ObjectStreamClass desc) throws IOException, ClassNotFoundException {
        if (!ALLOWED_CLASSES.contains(desc.getName())) {
            throw new InvalidClassException("Deserialization of this class is not permitted", desc.getName())
        }
        return super.resolveClass(desc)
    }
}

class BuildConfigImporter {

    def importConfigXml(String xmlContent) {
        // FIX (CWE-611): disable DOCTYPE declarations and external entity
        // resolution so XXE payloads cannot read local files or trigger SSRF.
        def parser = new XmlSlurper()
        parser.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
        parser.setFeature("http://xml.org/sax/features/external-general-entities", false)
        parser.setFeature("http://xml.org/sax/features/external-parameter-entities", false)
        def config = parser.parseText(xmlContent)
        return config.projectName.text()
    }

    def restoreBuildState(byte[] serializedState) {
        // FIX (CWE-502): use an allow-listing ObjectInputStream so only known,
        // non-executable data classes can be reconstructed from the byte stream.
        def ois = new SafeObjectInputStream(new ByteArrayInputStream(serializedState))
        def state = ois.readObject()
        ois.close()
        return state
    }
}

// Example invocation from a Jenkinsfile-style pipeline step
def importer = new BuildConfigImporter()
def uploadedXml = "<project><projectName>example</projectName></project>"
println importer.importConfigXml(uploadedXml)
