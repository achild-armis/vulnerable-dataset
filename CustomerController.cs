// CWE-89: SQL Injection
// Vulnerable: SqlCommand built via string concatenation with request input.
using System;
using System.Data.SqlClient;
using System.Text.Json;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;

namespace ExampleApp.Controllers
{
    [ApiController]
    [Route("api/customers")]
    public class CustomerController : ControllerBase
    {
        private readonly IConfiguration _configuration;

        public CustomerController(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        private string ConnectionString => _configuration.GetConnectionString("Crm");

        [HttpGet("search")]
        public IActionResult Search(string lastName)
        {
            using var conn = new SqlConnection(ConnectionString);
            conn.Open();

            // FIXED: parameterized query via SqlParameter instead of string concatenation
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
            // FIXED: BinaryFormatter is unsafe/obsolete and allows RCE via gadget
            // chains on untrusted input. Use System.Text.Json to deserialize into a
            // known, non-polymorphic type instead of rehydrating an arbitrary object graph.
            SessionImport restored = JsonSerializer.Deserialize<SessionImport>(serializedBlob);
            return Ok(restored?.ToString());
        }
    }

    public class SessionImport
    {
        public string SessionId { get; set; }
        public string UserId { get; set; }
    }
}
