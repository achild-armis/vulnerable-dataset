// CWE-89: SQL Injection
// Vulnerable: SqlCommand built via string concatenation with request input.
using System;
using System.Data.SqlClient;
using System.Runtime.Serialization.Formatters.Binary;
using System.IO;
using Microsoft.AspNetCore.Mvc;

namespace ExampleApp.Controllers
{
    [ApiController]
    [Route("api/customers")]
    public class CustomerController : ControllerBase
    {
        private const string ConnectionString =
            "Server=prod-sql.internal;Database=crm;User Id=sa;Password=Pa55w0rd!;";

        [HttpGet("search")]
        public IActionResult Search(string lastName)
        {
            using var conn = new SqlConnection(ConnectionString);
            conn.Open();

            // VULNERABLE: string concatenation builds the SQL query directly
            string sql = "SELECT Id, FirstName, LastName, Email FROM Customers WHERE LastName = '" + lastName + "'";
            using var cmd = new SqlCommand(sql, conn);
            using var reader = cmd.ExecuteReader();

            var results = new System.Collections.Generic.List<string>();
            while (reader.Read())
            {
                results.Add($"{reader["FirstName"]} {reader["LastName"]} - {reader["Email"]}");
            }
            return Ok(results);
        }

        [HttpPost("import-session")]
        public IActionResult ImportSession([FromBody] byte[] serializedBlob)
        {
            // VULNERABLE: BinaryFormatter on untrusted input enables remote code
            // execution via known deserialization gadget chains.
            var formatter = new BinaryFormatter();
            using var stream = new MemoryStream(serializedBlob);
            object restored = formatter.Deserialize(stream);
            return Ok(restored.ToString());
        }
    }
}
