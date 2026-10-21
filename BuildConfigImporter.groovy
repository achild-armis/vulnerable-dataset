// Fixed: CWE-611 XML External Entity (XXE) Injection and CWE-502
// Deserialization of Untrusted Data.
// XmlSlurper now uses a SAXParser with external entities and DTDs
// disabled, and the untrusted build-state blob is decoded as JSON
// instead of going through ObjectInputStream.
import groovy.xml.XmlSlurper
import groovy.json.JsonSlurper
import javax.xml.parsers.SAXParserFactory

class BuildConfigImporter {

    def importConfigXml(String xmlContent) {
        def factory = SAXParserFactory.newInstance()
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false)
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false)
        def parser = new XmlSlurper(factory.newSAXParser())
        def config = parser.parseText(xmlContent)
        return config.projectName.text()
    }

    def restoreBuildState(byte[] serializedState) {
        def state = new JsonSlurper().parse(serializedState)
        return state
    }
}

// Example invocation from a Jenkinsfile-style pipeline step
def importer = new BuildConfigImporter()
def uploadedXml = "<project><projectName>example</projectName></project>"
println importer.importConfigXml(uploadedXml)
