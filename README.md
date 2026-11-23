# Failed login attempt tracking

The application uses PostgreSQL, Spring Security sessions, JPA, and Flyway. Configure `DB_URL`, `DB_USERNAME`, and `DB_PASSWORD` before starting the application. The default URL is `jdbc:postgresql://localhost:5432/failed_login_attempt_tracking`; the database and credentials must already exist. Flyway applies `src/main/resources/db/migration` at startup, and Hibernate validates the resulting schema.

## Login API

Obtain a CSRF token first:

```http
GET /api/auth/csrf
```

The response contains a `token`; send it in the `X-XSRF-TOKEN` header when posting the login request. Preserve the CSRF cookie and session cookies between requests.

```http
POST /api/auth/login
Content-Type: application/json
X-XSRF-TOKEN: <token>

{"username":"alice","password":"..."}
```

A successful login returns `200` and establishes an HTTP session. Invalid credentials return `401`. Five consecutive invalid passwords lock that account; the next login attempt returns `423` with `lockedUntil` and `remainingSeconds`. A successful login resets the counter. Locked accounts are automatically unlocked when a login is attempted after 15 minutes.

There is deliberately no public account-registration or administrative unlock endpoint. Provision accounts through the trusted account administration process using a BCrypt password hash. To manually unlock one in PostgreSQL, set `account_non_locked = TRUE`, `failed_attempts = 0`, and `lock_time = NULL` for the intended user. Usernames are case-insensitive and unique.

Tests use an in-memory H2 database in PostgreSQL compatibility mode; production runtime configuration and Flyway migrations target PostgreSQL.
