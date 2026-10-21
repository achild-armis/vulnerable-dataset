// Fixed: CWE-89 SQL Injection (parameterized query), CWE-502
// Deserialization of Untrusted Data (BinaryFormatter replaced with a
// safe JSON deserializer), and CWE-798 Hard-coded Credentials
// (connection string now read from the environment).
using System;
using System.Data.SqlClient;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;

namespace ExampleApp.Controllers
{
    [ApiController]
    [Route("api/customers")]
    public class CustomerController : ControllerBase
    {
        private static readonly string ConnectionString =
            Environment.GetEnvironmentVariable("CRM_DB_CONNECTION_STRING");

        [HttpGet("search")]
        public IActionResult Search(string lastName)
        {
            using var conn = new SqlConnection(ConnectionString);
            conn.Open();

            string sql = "SELECT Id, FirstName, LastName, Email FROM Customers WHERE LastName = @LastName";
            using var cmd = new SqlCommand(sql, conn);
            cmd.Parameters.AddWithValue("@LastName", lastName);
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
            var restored = JsonSerializer.Deserialize<object>(serializedBlob);
            return Ok(restored?.ToString());
        }
    }
}
