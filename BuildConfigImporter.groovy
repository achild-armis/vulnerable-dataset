// CWE-611: XML External Entity (XXE) Injection
// CWE-502: Deserialization of Untrusted Data
// Vulnerable: Groovy script parses attacker-supplied XML with default,
// unsafe parser settings, and deserializes an untrusted object stream
// (a pattern frequently seen in Jenkins pipeline / Grails utility scripts).
import groovy.xml.XmlSlurper

class BuildConfigImporter {

    def importConfigXml(String xmlContent) {
        // VULNERABLE: XmlSlurper does not disable external entities or DTDs
        // by default, allowing XXE payloads to read local files or trigger SSRF.
        def parser = new XmlSlurper()
        def config = parser.parseText(xmlContent)
        return config.projectName.text()
    }

    def restoreBuildState(byte[] serializedState) {
        // VULNERABLE: ObjectInputStream deserializes attacker-controlled bytes,
        // enabling remote code execution via known gadget chains on the classpath.
        def ois = new ObjectInputStream(new ByteArrayInputStream(serializedState))
        def state = ois.readObject()
        ois.close()
        return state
    }
}

// Example invocation from a Jenkinsfile-style pipeline step
def importer = new BuildConfigImporter()
def uploadedXml = "<project><projectName>example</projectName></project>"
println importer.importConfigXml(uploadedXml)
