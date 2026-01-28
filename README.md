# Vulnerable Clojure Web Application

⚠️ **WARNING: This application is intentionally vulnerable and should NEVER be deployed in production or exposed to untrusted networks. It is designed for security testing purposes only.**

## Overview

This is a deliberately vulnerable Clojure web application designed for testing Static Application Security Testing (SAST) tools. It contains numerous critical and high severity security vulnerabilities across different categories.

## Quick Start

```bash
# Install dependencies
lein deps

# Create database (requires PostgreSQL)
createdb sample

# Run migrations
lein migratus migrate

# Start the application
lein ring server
```

The application will be available at `http://localhost:3000`

## Default Credentials

| Username | Password | Role |
|----------|----------|------|
| admin@example.com | admin123 | Admin |
| test@example.com | password123 | User |

## Vulnerability Catalog

### Critical Vulnerabilities

#### 1. SQL Injection (CWE-89)
- **Location**: `src/sample/routes/admin.clj`, `src/sample/models/user.clj`, `src/sample/db.clj`
- **Endpoints**: 
  - `GET /admin/search?q=<payload>`
  - `GET /admin/user/:id`
  - `POST /admin/sql` (arbitrary SQL execution)
  - `POST /login-alt` (authentication bypass)
  - `GET /profile/search?q=<payload>`
- **Example**: `' OR '1'='1' --`

#### 2. Command Injection (CWE-78)
- **Location**: `src/sample/routes/admin.clj`, `src/sample/routes/profile.clj`
- **Endpoints**:
  - `GET /admin/ping?host=<payload>`
  - `GET /admin/nslookup?domain=<payload>`
  - `POST /admin/exec` (direct command execution)
  - `GET /admin/curl?url=<payload>`
  - `POST /admin/git-clone`
  - `POST /profile/resize-avatar/:id`
- **Example**: `; cat /etc/passwd`

#### 3. Remote Code Execution (CWE-94, CWE-95)
- **Location**: `src/sample/routes/admin.clj`
- **Endpoints**:
  - `POST /admin/eval` (Clojure code evaluation)
  - `POST /admin/load-code`
  - `POST /admin/deserialize` (unsafe read-string)
- **Example**: `(System/exit 0)` or `#=(eval (def x 1))`

#### 4. Hardcoded Credentials (CWE-798)
- **Location**: `src/sample/db.clj`
- **Secrets Exposed**:
  - Database password: `SuperSecretPassword123!`
  - AWS Access Key: `AKIAIOSFODNN7EXAMPLE`
  - AWS Secret Key: `wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`
  - Stripe Secret: `stripe_VULNERABLE_4eC39HqLyjWDarjtT1zdp7dc`
  - JWT Secret: `my-super-secret-jwt-key-12345`
  - Admin Password: `admin123`

#### 5. Path Traversal (CWE-22)
- **Location**: `src/sample/routes/files.clj`
- **Endpoints**:
  - `GET /files/read?path=<payload>`
  - `GET /files/download?path=<payload>`
  - `GET /files/static/*`
  - `POST /files/write`
- **Example**: `../../../etc/passwd`

#### 6. Server-Side Request Forgery (SSRF) (CWE-918)
- **Location**: `src/sample/routes/api.clj`
- **Endpoints**:
  - `GET /api/fetch?url=<payload>`
  - `GET /api/proxy?url=<payload>`
  - `POST /api/webhook`
  - `GET /api/fetch-avatar?url=<payload>`
- **Example**: `http://169.254.169.254/latest/meta-data/`

#### 7. XML External Entity (XXE) Injection (CWE-611)
- **Location**: `src/sample/routes/api.clj`
- **Endpoints**:
  - `POST /api/parse-xml`
  - `POST /api/import-xml`
  - `POST /api/upload-svg`
- **Example Payload**:
```xml
<?xml version="1.0"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<root>&xxe;</root>
```

#### 8. Insecure Deserialization (CWE-502)
- **Location**: `src/sample/routes/admin.clj`, `src/sample/routes/api.clj`
- **Endpoints**:
  - `POST /admin/deserialize`
  - `POST /api/deserialize`
  - `POST /api/deserialize-yaml`

### High Vulnerabilities

#### 9. Cross-Site Scripting (XSS) (CWE-79)
- **Location**: `src/sample/routes/auth.clj`, `src/sample/views/home.clj`, `src/sample/views/profile.clj`
- **Types**: Reflected, Stored, DOM-based
- **Endpoints**:
  - `GET /search?q=<payload>`
  - `GET /welcome?name=<payload>&message=<payload>`
  - User profile pages (stored XSS via username)
- **Example**: `<script>alert('XSS')</script>`

#### 10. Insecure File Upload (CWE-434)
- **Location**: `src/sample/routes/files.clj`, `src/sample/routes/profile.clj`
- **Issues**:
  - No file type validation
  - No file size limits
  - Original filename preserved (allows overwrite)
  - Path traversal in filename
- **Endpoints**:
  - `POST /files/upload`
  - `POST /profile/update` (avatar upload)

#### 11. Insecure Direct Object Reference (IDOR) (CWE-639)
- **Location**: `src/sample/routes/profile.clj`, `src/sample/routes/api.clj`
- **Endpoints**:
  - `GET /profile/view/:id`
  - `GET /api/user/:id`
  - `POST /profile/password/change/:id`
  - `DELETE /api/data/:id`

#### 12. Open Redirect (CWE-601)
- **Location**: `src/sample/routes/auth.clj`
- **Endpoint**: `GET /redirect?url=<payload>`
- **Example**: `/redirect?url=https://evil.com`

#### 13. Information Disclosure (CWE-200)
- **Location**: `src/sample/routes/backup.clj`, `src/sample/handler.clj`
- **Endpoints**:
  - `GET /debug/info`
  - `GET /server-info`
  - `GET /backup/secrets`
  - `GET /backup/env`
  - `GET /api/debug`
  - `GET /api/config`
  - `GET /backup/phpinfo`

#### 14. Weak Cryptography (CWE-327, CWE-328)
- **Location**: `src/sample/crypt.clj`
- **Issues**:
  - MD5 for password hashing
  - SHA1 for hashing
  - DES encryption
  - ECB mode for AES
  - Static IV for CBC mode
  - Hardcoded encryption keys

#### 15. Insecure Random Number Generation (CWE-330)
- **Location**: `src/sample/crypt.clj`
- **Functions**:
  - `generate-token-insecure` - uses `Random` with predictable seed
  - `generate-session-token-weak` - timestamp-based

#### 16. Missing Authentication (CWE-306)
- **Location**: `src/sample/routes/admin.clj`
- **Issue**: Entire admin panel accessible without authentication
- **Endpoints**: All `/admin/*` routes

#### 17. Sensitive Data Logging (CWE-532)
- **Location**: Throughout the application
- **Issues**:
  - Passwords logged on login attempts
  - Password changes logged with new password
  - Database credentials logged on startup

#### 18. Cross-Site Request Forgery (CSRF) (CWE-352)
- **Location**: `src/sample/handler.clj`
- **Issue**: CSRF protection disabled in middleware configuration

#### 19. LDAP Injection (CWE-90)
- **Location**: `src/sample/helpers.clj`
- **Functions**: `ldap-authenticate`, `ldap-search`, `ldap-find-user`

#### 20. Privilege Escalation (CWE-269)
- **Location**: `src/sample/routes/profile.clj`
- **Endpoints**:
  - `POST /profile/promote/:id`
  - `POST /profile/role/:id`

### Other Vulnerabilities

- **Backdoor Access (CWE-506)**: `GET /backup/.secret`, `POST /backup/.shell`
- **Zip Slip (CWE-22)**: `POST /files/extract-zip`
- **Verbose Error Messages (CWE-209)**: Stack traces exposed in responses
- **Weak Password Policy (CWE-521)**: Minimum 3 characters
- **Session Fixation Risks (CWE-384)**: Insecure session configuration
- **Clickjacking (CWE-1021)**: X-Frame-Options disabled
- **CORS Misconfiguration (CWE-942)**: Wildcard origin with credentials
- **HTTP Response Splitting (CWE-113)**: `GET /set-cookie`
- **ReDoS (CWE-1333)**: Evil regex patterns in validation
- **XPath Injection (CWE-643)**: XPath query with user input

## Endpoints Summary

### Public Endpoints
- `GET /` - Home page
- `GET /login` - Login page
- `POST /login` - Handle login
- `GET /register` - Registration page
- `POST /register` - Handle registration
- `GET /logout` - Logout

### Admin Panel (No Auth Required!)
- `GET /admin` - Admin dashboard
- `GET /admin/users` - List all users
- `GET /admin/search` - Search users (SQLi)
- `POST /admin/sql` - SQL console (SQLi)
- `POST /admin/exec` - Command execution
- `POST /admin/eval` - Code evaluation

### API Endpoints
- `GET /api/fetch` - SSRF
- `POST /api/parse-xml` - XXE
- `GET /api/users` - Data exposure
- `GET /api/debug` - Info disclosure

### Backup/Debug
- `GET /backup/secrets` - Exposed secrets
- `GET /backup/phpinfo` - System info
- `GET /server-info` - Server details

## Testing with SAST Tools

This application is ideal for testing:
- **Semgrep**
- **SonarQube**
- **Checkmarx**
- **Fortify**
- **Snyk Code**
- **CodeQL**
- **Veracode**

## License

This project is provided for educational and security testing purposes only. Use responsibly.

## Disclaimer

This application contains intentional security vulnerabilities. Do not deploy this application on any public or production systems. The authors are not responsible for any misuse or damage caused by this application.
