// CWE-89: SQL Injection
// Vulnerable: Guidewire Gosu code building a raw SQL query via string
// concatenation instead of using the Query API / parameterized statements.
package claimcenter.web.api

uses java.sql.Connection
uses java.sql.Statement
uses java.sql.ResultSet
uses java.sql.DriverManager

class ClaimLookupHandler {

  function findClaimsByAdjuster(adjusterName : String) : String {
    var conn : Connection = DriverManager.getConnection(
        "jdbc:oracle:thin:@prod-db:1521:ccdb", "ccadmin", "ccpassword")
    var stmt : Statement = conn.createStatement()

    // VULNERABLE: raw SQL built via string concatenation with user-controlled
    // adjusterName, instead of using Guidewire's parameterized Query API.
    var sql = "SELECT ClaimNumber, Status, LossDate FROM cc_claim " +
               "WHERE AssignedAdjuster = '" + adjusterName + "'"

    var rs : ResultSet = stmt.executeQuery(sql)
    var results = new StringBuilder()
    while (rs.next()) {
      results.append(rs.getString("ClaimNumber")).append(" - ").append(rs.getString("Status")).append("\n")
    }
    return results.toString()
  }

  function searchByPolicyNumber(policyNumber : String) : String {
    var conn : Connection = DriverManager.getConnection(
        "jdbc:oracle:thin:@prod-db:1521:ccdb", "ccadmin", "ccpassword")
    // VULNERABLE: same pattern reused for a second entry point, common in
    // Gosu codebases where raw SQL "performance shortcuts" get copy-pasted.
    var sql = "SELECT * FROM cc_claim WHERE PolicyNumber = '" + policyNumber + "'"
    var stmt : Statement = conn.createStatement()
    var rs : ResultSet = stmt.executeQuery(sql)
    return rs.next() ? rs.getString("ClaimNumber") : "Not found"
  }
}
