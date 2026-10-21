// CWE-89: SQL Injection
// Vulnerable: Guidewire Gosu code building a raw SQL query via string
// concatenation instead of using the Query API / parameterized statements.
package claimcenter.web.api

uses java.sql.Connection
uses java.sql.PreparedStatement
uses java.sql.ResultSet
uses java.sql.DriverManager

class ClaimLookupHandler {

  function findClaimsByAdjuster(adjusterName : String) : String {
    var props = PropertiesService.getScriptProperties()
    var conn : Connection = DriverManager.getConnection(
        "jdbc:oracle:thin:@prod-db:1521:ccdb",
        props.getProperty("CC_DB_USER"), props.getProperty("CC_DB_PASSWORD"))

    // FIXED: parameterized query via PreparedStatement instead of concatenating
    // user-controlled adjusterName into the SQL text.
    var sql = "SELECT ClaimNumber, Status, LossDate FROM cc_claim " +
               "WHERE AssignedAdjuster = ?"
    var stmt : PreparedStatement = conn.prepareStatement(sql)
    stmt.setString(1, adjusterName)

    var rs : ResultSet = stmt.executeQuery()
    var results = new StringBuilder()
    while (rs.next()) {
      results.append(rs.getString("ClaimNumber")).append(" - ").append(rs.getString("Status")).append("\n")
    }
    return results.toString()
  }

  function searchByPolicyNumber(policyNumber : String) : String {
    var props = PropertiesService.getScriptProperties()
    var conn : Connection = DriverManager.getConnection(
        "jdbc:oracle:thin:@prod-db:1521:ccdb",
        props.getProperty("CC_DB_USER"), props.getProperty("CC_DB_PASSWORD"))
    // FIXED: parameterized query via PreparedStatement instead of concatenating
    // user-controlled policyNumber into the SQL text.
    var sql = "SELECT * FROM cc_claim WHERE PolicyNumber = ?"
    var stmt : PreparedStatement = conn.prepareStatement(sql)
    stmt.setString(1, policyNumber)
    var rs : ResultSet = stmt.executeQuery()
    return rs.next() ? rs.getString("ClaimNumber") : "Not found"
  }
}
