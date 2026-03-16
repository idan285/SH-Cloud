// ============================================================================
// HrApi - Vulnerable .NET Web API for AppSec Training
// קובץ הדגמה לצוות AppSec - חולשות נפוצות ב-API
// סרקו עם Checkmarx One SAST ובדקו מה נמצא ומה לא
// ============================================================================

using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using System.Data.SqlClient;
using System.Text;
using System.Security.Cryptography;
using System.Xml;
using System.Diagnostics;

namespace HrApi;

// ============================================================================
// MODELS
// ============================================================================

public class Employee
{
    public int Id { get; set; }
    public string FirstName { get; set; }
    public string LastName { get; set; }
    public string Email { get; set; }
    public string Password { get; set; }           // VULN: password in model
    public string SSN { get; set; }                // VULN: PII in base model
    public string Role { get; set; }
    public decimal Salary { get; set; }
    public string BankAccount { get; set; }        // VULN: financial data in model
    public string Department { get; set; }
    public bool IsActive { get; set; }
    public string ManagerNotes { get; set; }       // VULN: internal field exposed
}

public class LoginRequest
{
    public string Username { get; set; }
    public string Password { get; set; }
}

public class HrDbContext : DbContext
{
    public HrDbContext(DbContextOptions<HrDbContext> options) : base(options) { }
    public DbSet<Employee> Employees { get; set; }
}

// ============================================================================
// AUTH CONTROLLER
// ============================================================================

[ApiController]
[Route("api/auth")]
public class AuthController : ControllerBase
{
    private readonly HrDbContext _db;

    public AuthController(HrDbContext db) { _db = db; }

    // VULN: Broken Authentication - API2:2023
    // MD5 comparison, no lockout, no MFA, token never expires
    [HttpPost("login")]
    public async Task<ActionResult> Login([FromBody] LoginRequest request)
    {
        // VULN: SQL Injection in authentication flow
        var connStr = "Server=hr-db;Database=HrApp;User=sa;Password=HrProd2024!;";
        using var conn = new SqlConnection(connStr);
        conn.Open();
        var query = "SELECT * FROM Employees WHERE Email = '" + request.Username
                    + "' AND Password = '" + request.Password + "'";
        using var cmd = new SqlCommand(query, conn);
        using var reader = cmd.ExecuteReader();

        if (reader.Read())
        {
            // VULN: Hardcoded secret, weak algorithm, no expiration
            var tokenData = $"{{\"user\":\"{request.Username}\",\"role\":\"{reader["Role"]}\"}}";
            var token = Convert.ToBase64String(Encoding.UTF8.GetBytes(tokenData));
            return Ok(new { token = token, message = "Login successful" });
        }

        // VULN: Reveals whether user exists (different message for wrong password)
        return Unauthorized(new { message = "Invalid password for this account" });
    }

    // -------------------------------------------------------------------
    // ZOMBIE endpoint: v1 login that was "replaced" but never removed
    // Still works, uses even weaker security
    // -------------------------------------------------------------------
    [HttpPost("/api/v1/auth/login")]
    public ActionResult LoginV1([FromBody] LoginRequest request)
    {
        // VULN: MD5 password hash, no salt
        using var md5 = MD5.Create();
        var hash = Convert.ToBase64String(
            md5.ComputeHash(Encoding.UTF8.GetBytes(request.Password)));

        // VULN: Token is just base64 with no signature
        var token = Convert.ToBase64String(
            Encoding.UTF8.GetBytes($"{{\"user\":\"{request.Username}\",\"admin\":true}}"));

        return Ok(new { token });
    }
}

// ============================================================================
// EMPLOYEES CONTROLLER - main CRUD
// ============================================================================

[ApiController]
[Route("api/employees")]
public class EmployeesController : ControllerBase
{
    private readonly HrDbContext _db;
    private readonly ILogger<EmployeesController> _logger;

    public EmployeesController(HrDbContext db, ILogger<EmployeesController> logger)
    {
        _db = db;
        _logger = logger;
    }

    // VULN: Excessive Data Exposure - API3:2023
    // Returns ALL fields including SSN, salary, bank account, password
    // No DTO, no field filtering
    [HttpGet]
    public async Task<ActionResult> GetAll(
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 5000)   // VULN: huge default page size
    {
        // VULN: No max pageSize enforcement - Unrestricted Resource Consumption (API4:2023)
        // VULN: No authorization - anyone can list all employees
        var employees = await _db.Employees
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();

        // VULN: Logs sensitive query info
        _logger.LogInformation($"User fetched {employees.Count} employees, page={page}");

        return Ok(employees);
    }

    // VULN: BOLA - Broken Object Level Authorization - API1:2023
    // No check that the requesting user can access this employee
    [HttpGet("{id}")]
    public async Task<ActionResult<Employee>> GetById(int id)
    {
        var emp = await _db.Employees.FindAsync(id);
        if (emp == null)
            return NotFound(new { message = $"Employee {id} not found in department DB" });

        return Ok(emp);  // VULN: returns full object including PII
    }

    // VULN: Mass Assignment - API6:2023
    // Binds directly to Employee model - client can set Role, Salary, etc.
    [HttpPost]
    public async Task<ActionResult> Create([FromBody] Employee employee)
    {
        // VULN: No input validation at all
        // VULN: Client can set Role = "Admin" and Salary = 999999
        // VULN: Password stored as plaintext
        _db.Employees.Add(employee);
        await _db.SaveChangesAsync();

        // VULN: Sensitive data in logs
        _logger.LogInformation(
            $"Created employee: {employee.Email}, SSN: {employee.SSN}, Role: {employee.Role}");

        return CreatedAtAction(nameof(GetById), new { id = employee.Id }, employee);
    }

    // VULN: BOLA on update + Mass Assignment
    [HttpPut("{id}")]
    public async Task<ActionResult> Update(int id, [FromBody] Employee updated)
    {
        var emp = await _db.Employees.FindAsync(id);
        if (emp == null) return NotFound();

        // VULN: No check that requesting user owns or manages this employee
        // VULN: ALL fields overwritten from user input including Role and Salary
        emp.FirstName = updated.FirstName;
        emp.LastName = updated.LastName;
        emp.Email = updated.Email;
        emp.Role = updated.Role;             // VULN: privilege escalation
        emp.Salary = updated.Salary;         // VULN: salary manipulation
        emp.SSN = updated.SSN;
        emp.BankAccount = updated.BankAccount;
        emp.Password = updated.Password;     // VULN: password change without verification

        await _db.SaveChangesAsync();
        return Ok(emp);
    }

    // VULN: Broken Function Level Authorization - API5:2023
    // Delete should require Admin role but has no auth at all
    [HttpDelete("{id}")]
    public async Task<ActionResult> Delete(int id)
    {
        var emp = await _db.Employees.FindAsync(id);
        if (emp == null) return NotFound();

        _db.Employees.Remove(emp);
        await _db.SaveChangesAsync();
        return NoContent();
    }

    // VULN: SQL Injection via search
    [HttpGet("search")]
    public ActionResult Search([FromQuery] string q, [FromQuery] string fields)
    {
        var connStr = "Server=hr-db;Database=HrApp;User=sa;Password=HrProd2024!;";
        using var conn = new SqlConnection(connStr);
        conn.Open();

        // VULN: SQL Injection - string concatenation
        // VULN: field selection from user input - data exposure
        var selectedFields = string.IsNullOrEmpty(fields) ? "*" : fields;
        var query = $"SELECT {selectedFields} FROM Employees WHERE "
                    + $"FirstName LIKE '%{q}%' OR LastName LIKE '%{q}%' OR Email LIKE '%{q}%'";

        using var cmd = new SqlCommand(query, conn);
        using var reader = cmd.ExecuteReader();

        var results = new List<Dictionary<string, object>>();
        while (reader.Read())
        {
            var row = new Dictionary<string, object>();
            for (int i = 0; i < reader.FieldCount; i++)
                row[reader.GetName(i)] = reader.GetValue(i);
            results.Add(row);
        }

        return Ok(results);
    }

    // -------------------------------------------------------------------
    // ZOMBIE endpoint: v1 bulk export that was "deprecated" but still works
    // -------------------------------------------------------------------
    [HttpGet("/api/v1/employees/export")]
    public async Task<ActionResult> ExportV1([FromQuery] string format = "csv")
    {
        // VULN: No auth, full PII export, no audit logging
        var employees = await _db.Employees.ToListAsync();
        var csv = new StringBuilder("Id,Name,Email,SSN,Password,Salary,BankAccount\n");
        foreach (var e in employees)
        {
            csv.AppendLine($"{e.Id},{e.FirstName} {e.LastName},{e.Email}," +
                           $"{e.SSN},{e.Password},{e.Salary},{e.BankAccount}");
        }

        return File(Encoding.UTF8.GetBytes(csv.ToString()), "text/csv", "employees_export.csv");
    }
}

// ============================================================================
// SALARY CONTROLLER - payroll operations
// ============================================================================

[ApiController]
[Route("api/employees/{employeeId}/salary")]
public class SalaryController : ControllerBase
{
    private readonly HrDbContext _db;

    public SalaryController(HrDbContext db) { _db = db; }

    [HttpPut]
    public async Task<ActionResult> UpdateSalary(
        int employeeId,
        [FromBody] SalaryUpdateRequest request)
    {
        // VULN: BOLA - no check that requester can modify this employee's salary
        var emp = await _db.Employees.FindAsync(employeeId);
        if (emp == null) return NotFound();

        var previousSalary = emp.Salary;
        emp.Salary = request.NewSalary;    // VULN: no min/max validation
        await _db.SaveChangesAsync();

        // VULN: exposes previous salary in response
        return Ok(new
        {
            employeeId,
            previousSalary,
            newSalary = emp.Salary,
            approvedBy = request.ApprovedBy  // VULN: client-supplied approval
        });
    }

    [HttpGet("/api/reports/payroll")]
    public async Task<ActionResult> PayrollReport(
        [FromQuery] string department,
        [FromQuery] bool includeSSN = true,      // VULN: PII included by default
        [FromQuery] bool includeBankInfo = true)  // VULN: financial data by default
    {
        var query = _db.Employees.AsQueryable();
        if (!string.IsNullOrEmpty(department))
            query = query.Where(e => e.Department == department);

        var employees = await query.ToListAsync();
        // VULN: returns full objects with PII based on query params
        return Ok(employees);
    }
}

public class SalaryUpdateRequest
{
    public decimal NewSalary { get; set; }
    public string ApprovedBy { get; set; }    // VULN: client specifies approver
    public string EffectiveDate { get; set; }
}

// ============================================================================
// DOCUMENTS CONTROLLER - file upload
// ============================================================================

[ApiController]
[Route("api/employees/{employeeId}/documents")]
public class DocumentsController : ControllerBase
{
    // VULN: Unrestricted File Upload - no auth, no type checking, no size limit
    [HttpPost]
    public async Task<ActionResult> Upload(int employeeId, IFormFile file)
    {
        // VULN: No file type validation - can upload .exe, .aspx, web shells
        // VULN: No file size validation
        // VULN: Path traversal possible via filename
        var filePath = Path.Combine("/var/www/uploads/employees",
                                    employeeId.ToString(),
                                    file.FileName);  // VULN: unsanitized filename

        Directory.CreateDirectory(Path.GetDirectoryName(filePath));
        using var stream = new FileStream(filePath, FileMode.Create);
        await file.CopyToAsync(stream);

        return Ok(new
        {
            fileUrl = $"https://storage.company.com/docs/emp_{employeeId}/{file.FileName}",
            filePath = filePath   // VULN: internal server path exposed
        });
    }
}

// ============================================================================
// IMPORT CONTROLLER - SSRF vulnerability
// ============================================================================

[ApiController]
[Route("api/employees/import-photo")]
public class ImportController : ControllerBase
{
    // VULN: SSRF - Server-Side Request Forgery - API7:2023
    [HttpPost]
    public async Task<ActionResult> ImportPhoto([FromBody] ImportPhotoRequest request)
    {
        // VULN: No URL validation, no allowlist
        // Attacker can request: http://169.254.169.254/latest/meta-data/ (cloud metadata)
        // Or: http://hr-db:5432/ (internal database)
        // Or: http://10.128.0.15:8080/api/config (internal services)
        using var httpClient = new HttpClient();
        var response = await httpClient.GetAsync(request.PhotoUrl);
        var content = await response.Content.ReadAsByteArrayAsync();

        // VULN: No content-type validation on response
        await System.IO.File.WriteAllBytesAsync(
            $"/var/www/uploads/photos/{request.EmployeeId}.jpg", content);

        return Ok(new { message = "Photo imported" });
    }
}

public class ImportPhotoRequest
{
    public int EmployeeId { get; set; }
    public string PhotoUrl { get; set; }
}

// ============================================================================
// SHADOW API ENDPOINTS
// These exist in code but are NOT documented in the Swagger file
// Checkmarx API Security compares spec vs actual traffic to find these
// ============================================================================

[ApiController]
[Route("api/debug")]
public class DebugController : ControllerBase
{
    // SHADOW API #1: health/diagnostics endpoint
    // DevOps added this for GKE health checks - publicly accessible, no auth
    [HttpGet("health")]
    public ActionResult Health()
    {
        return Ok(new
        {
            status = "healthy",
            database = "connected",
            server = Environment.MachineName,
            os = Environment.OSVersion.ToString(),
            memory = GC.GetTotalMemory(false),
            uptime = Environment.TickCount64,
            env = Environment.GetEnvironmentVariables()  // VULN: all env vars exposed
        });
    }
}

[ApiController]
[Route("api/admin")]
public class AdminController : ControllerBase
{
    private readonly HrDbContext _db;

    public AdminController(HrDbContext db) { _db = db; }

    // SHADOW API #2: impersonate endpoint - no auth, no audit
    [HttpPost("impersonate/{userId}")]
    public async Task<ActionResult> Impersonate(int userId)
    {
        var user = await _db.Employees.FindAsync(userId);
        if (user == null) return NotFound();

        var token = Convert.ToBase64String(
            Encoding.UTF8.GetBytes($"{{\"user\":\"{user.Email}\",\"role\":\"{user.Role}\"}}"));

        return Ok(new { token, impersonating = user.Email });
    }

    // SHADOW API #3: raw SQL execution endpoint - left from debugging
    [HttpPost("query")]
    public ActionResult ExecuteQuery([FromBody] string sql)
    {
        // VULN: Direct SQL execution from user input - catastrophic
        var connStr = "Server=hr-db;Database=HrApp;User=sa;Password=HrProd2024!;";
        using var conn = new SqlConnection(connStr);
        conn.Open();
        using var cmd = new SqlCommand(sql, conn);
        using var reader = cmd.ExecuteReader();

        var results = new List<Dictionary<string, object>>();
        while (reader.Read())
        {
            var row = new Dictionary<string, object>();
            for (int i = 0; i < reader.FieldCount; i++)
                row[reader.GetName(i)] = reader.GetValue(i);
            results.Add(row);
        }

        return Ok(results);
    }
}

[ApiController]
[Route("api/config")]
public class ConfigController : ControllerBase
{
    // SHADOW API #4: application config dump
    [HttpGet]
    public ActionResult GetConfig()
    {
        // VULN: Exposes all application secrets
        return Ok(new
        {
            dbConnectionString = "Server=hr-db;Database=HrApp;User=sa;Password=HrProd2024!;",
            jwtSecret = "MySuperSecretKeyThatShouldNotBeHere123",
            storageAccount = "DefaultEndpointsProtocol=https;AccountName=hrfiles;AccountKey=abc123==",
            smtpPassword = "EmailPass2024!",
            apiKeys = new
            {
                google = "AIzaSyFakeKeyForDemo12345",
                stripe = "sk_live_FakeStripeKeyForDemo"
            }
        });
    }
}

// ============================================================================
// CRYPTO HELPER - weak cryptography shared across the API
// ============================================================================

public static class CryptoHelper
{
    // VULN: MD5 for password hashing - broken algorithm
    public static string HashPassword(string password)
    {
        using var md5 = MD5.Create();
        return Convert.ToBase64String(md5.ComputeHash(Encoding.UTF8.GetBytes(password)));
    }

    // VULN: Hardcoded key + DES encryption (broken cipher)
    private static readonly byte[] EncryptionKey = Encoding.UTF8.GetBytes("WeakKey!");

    public static byte[] Encrypt(string data)
    {
        using var des = DES.Create();
        des.Key = EncryptionKey;
        des.IV = EncryptionKey;   // VULN: IV = Key
        using var enc = des.CreateEncryptor();
        var bytes = Encoding.UTF8.GetBytes(data);
        return enc.TransformFinalBlock(bytes, 0, bytes.Length);
    }
}

// ============================================================================
// Program.cs - Startup with security misconfigurations
// ============================================================================

public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        builder.Services.AddControllers();
        builder.Services.AddEndpointsApiExplorer();
        builder.Services.AddSwaggerGen();

        // VULN: Hardcoded connection string with SA credentials
        builder.Services.AddDbContext<HrDbContext>(options =>
            options.UseSqlServer("Server=hr-db;Database=HrApp;User=sa;Password=HrProd2024!;"));

        // VULN: CORS allows everything
        builder.Services.AddCors(o => o.AddDefaultPolicy(p =>
            p.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader()));

        var app = builder.Build();

        // VULN: Swagger enabled unconditionally (should be dev-only)
        app.UseSwagger();
        app.UseSwaggerUI();

        // VULN: Developer exception page in production
        app.UseDeveloperExceptionPage();

        // VULN: No HTTPS enforcement
        // VULN: No authentication middleware
        // VULN: No rate limiting
        // VULN: No security headers (CSP, X-Frame-Options, HSTS)

        app.UseCors();
        app.MapControllers();
        app.Run();
    }
}
