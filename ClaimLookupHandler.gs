// Fixed: CWE-89 SQL Injection and CWE-798 Hard-coded Credentials.
// Both lookups now use PreparedStatement with bound parameters, and the
// database credentials are read from the environment instead of being
// committed to source control.
package claimcenter.web.api

uses java.sql.Connection
uses java.sql.PreparedStatement
uses java.sql.ResultSet
uses java.sql.DriverManager

class ClaimLookupHandler {

  private static final var MAX_RESULT_ROWS = 500

  private function getConnection() : Connection {
    return DriverManager.getConnection(
        "jdbc:oracle:thin:@prod-db:1521:ccdb",
        System.getenv("CC_DB_USER"), System.getenv("CC_DB_PASSWORD"))
  }

  function findClaimsByAdjuster(adjusterName : String) : String {
    var conn : Connection = getConnection()
    try {
      var sql = "SELECT ClaimNumber, Status, LossDate FROM cc_claim " +
                 "WHERE AssignedAdjuster = ?"
      var stmt : PreparedStatement = conn.prepareStatement(sql)
      try {
        stmt.setString(1, adjusterName)
        stmt.setMaxRows(MAX_RESULT_ROWS)
        var rs : ResultSet = stmt.executeQuery()
        try {
          var results = new StringBuilder()
          var rowCount = 0
          while (rs.next() && rowCount < MAX_RESULT_ROWS) {
            results.append(rs.getString("ClaimNumber")).append(" - ").append(rs.getString("Status")).append("\n")
            rowCount++
          }
          return results.toString()
        } finally {
          rs.close()
        }
      } finally {
        stmt.close()
      }
    } finally {
      conn.close()
    }
  }

  function searchByPolicyNumber(policyNumber : String) : String {
    var conn : Connection = getConnection()
    try {
      var sql = "SELECT * FROM cc_claim WHERE PolicyNumber = ?"
      var stmt : PreparedStatement = conn.prepareStatement(sql)
      try {
        stmt.setString(1, policyNumber)
        var rs : ResultSet = stmt.executeQuery()
        try {
          return rs.next() ? rs.getString("ClaimNumber") : "Not found"
        } finally {
          rs.close()
        }
      } finally {
        stmt.close()
      }
    } finally {
      conn.close()
    }
  }
}
