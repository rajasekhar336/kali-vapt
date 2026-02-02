# Laravel REST API Specification

## Overview

This document describes the Laravel REST API endpoints required for the VAPT Dashboard frontend.
All endpoints use JSON for request/response bodies and Laravel Sanctum for SPA authentication.

---

## Technology Stack

- **Framework**: Laravel 11.x
- **Database**: MySQL 8.x
- **Authentication**: Laravel Sanctum (SPA mode)
- **API Format**: JSON REST

---

## Authentication (Laravel Sanctum)

### Prerequisites

1. Install Laravel Sanctum:
```bash
composer require laravel/sanctum
php artisan vendor:publish --provider="Laravel\Sanctum\SanctumServiceProvider"
php artisan migrate
```

2. Configure `config/sanctum.php`:
```php
'stateful' => explode(',', env('SANCTUM_STATEFUL_DOMAINS', sprintf(
    '%s%s',
    'localhost,localhost:3000,localhost:5173,127.0.0.1,127.0.0.1:8000,::1',
    env('APP_URL') ? ','.parse_url(env('APP_URL'), PHP_URL_HOST) : ''
))),
```

3. Configure CORS in `config/cors.php`:
```php
'paths' => ['api/*', 'sanctum/csrf-cookie'],
'allowed_origins' => ['http://localhost:5173', 'http://localhost:3000'],
'supports_credentials' => true,
```

4. Add Sanctum middleware to `app/Http/Kernel.php`:
```php
'api' => [
    \Laravel\Sanctum\Http\Middleware\EnsureFrontendRequestsAreStateful::class,
    // ...
],
```

---

### GET /sanctum/csrf-cookie

Get CSRF cookie before making state-changing requests.

**Response (204 No Content)**
Sets `XSRF-TOKEN` cookie.

---

### POST /api/login

Authenticate analyst and create session.

**Request:**
```json
{
  "email": "analyst@example.com",
  "password": "securepassword"
}
```

**Response (200 OK):**
```json
{
  "user": {
    "id": 1,
    "username": "analyst1",
    "email": "analyst@example.com",
    "role": "analyst"
  }
}
```

**Response (422 Validation Error):**
```json
{
  "message": "The given data was invalid.",
  "errors": {
    "email": ["The email field is required."],
    "password": ["The password is incorrect."]
  }
}
```

**Laravel Controller:**
```php
public function login(Request $request)
{
    $credentials = $request->validate([
        'email' => 'required|email',
        'password' => 'required',
    ]);

    if (!Auth::attempt($credentials)) {
        throw ValidationException::withMessages([
            'email' => ['The provided credentials are incorrect.'],
        ]);
    }

    $request->session()->regenerate();

    return response()->json([
        'user' => Auth::user()->only(['id', 'name', 'email', 'role']),
    ]);
}
```

---

### POST /api/logout

Destroy session.

**Response (200 OK):**
```json
{
  "message": "Logged out successfully"
}
```

**Laravel Controller:**
```php
public function logout(Request $request)
{
    Auth::guard('web')->logout();
    $request->session()->invalidate();
    $request->session()->regenerateToken();

    return response()->json(['message' => 'Logged out successfully']);
}
```

---

### GET /api/user

Check current authenticated user.

**Response (200 OK):**
```json
{
  "id": 1,
  "username": "analyst1",
  "email": "analyst@example.com",
  "role": "analyst"
}
```

**Response (401 Unauthenticated):**
```json
{
  "message": "Unauthenticated."
}
```

---

## Domains

### GET /api/domains

Fetch all domains with summaries.

**Response (200 OK):**
```json
{
  "data": [
    {
      "id": "domain-1",
      "domain_name": "target.com",
      "scan_status": "completed",
      "security_score": 72,
      "total": 8,
      "critical": 2,
      "high": 2,
      "medium": 2,
      "low": 2,
      "validated": 4,
      "false_positives": 1,
      "needs_review": 1,
      "pending": 2,
      "last_scan_at": "2026-01-15T10:00:00Z",
      "created_at": "2026-01-10T08:00:00Z"
    }
  ]
}
```

**Laravel Controller:**
```php
public function index()
{
    $domains = Domain::withCount([
        'findings as total',
        'findings as critical' => fn($q) => $q->where('severity', 'critical'),
        'findings as high' => fn($q) => $q->where('severity', 'high'),
        'findings as medium' => fn($q) => $q->where('severity', 'medium'),
        'findings as low' => fn($q) => $q->where('severity', 'low'),
        'findings as validated' => fn($q) => $q->where('validation_status', 'validated'),
        'findings as false_positives' => fn($q) => $q->where('validation_status', 'false_positive'),
        'findings as needs_review' => fn($q) => $q->where('validation_status', 'needs_review'),
        'findings as pending' => fn($q) => $q->where('validation_status', 'pending'),
    ])->get();

    return DomainResource::collection($domains);
}
```

---

### GET /api/domains/{domain}

Fetch single domain details.

**Response (200 OK):**
```json
{
  "data": {
    "id": "domain-1",
    "domain_name": "target.com",
    "scan_status": "completed",
    "current_phase": null,
    "security_score": 72,
    "last_scan_at": "2026-01-15T10:00:00Z",
    "created_at": "2026-01-10T08:00:00Z"
  }
}
```

---

### POST /api/domains

Create a new domain and trigger full scan.

**Request:**
```json
{
  "domain_name": "newsite.com"
}
```

**Response (201 Created):**
```json
{
  "data": {
    "id": "domain-5",
    "domain_name": "newsite.com",
    "scan_status": "queued",
    "security_score": 0,
    "created_at": "2026-01-19T12:00:00Z"
  },
  "message": "Domain created and scan queued"
}
```

**Laravel Controller:**
```php
public function store(Request $request)
{
    $validated = $request->validate([
        'domain_name' => 'required|string|max:253|unique:domains,domain_name',
    ]);

    $domain = Domain::create([
        'domain_name' => $validated['domain_name'],
        'scan_status' => 'queued',
        'security_score' => 0,
    ]);

    // Dispatch scan job
    StartDomainScan::dispatch($domain);

    return (new DomainResource($domain))
        ->additional(['message' => 'Domain created and scan queued'])
        ->response()
        ->setStatusCode(201);
}
```

---

### POST /api/domains/{domain}/scans

Start a new full scan for a domain.

**Response (202 Accepted):**
```json
{
  "data": {
    "id": "scan-123",
    "domain_id": "domain-1",
    "status": "scanning",
    "current_phase": "reconnaissance",
    "started_at": "2026-01-19T12:00:00Z"
  },
  "message": "Scan started"
}
```

---

### GET /api/domains/{domain}/scan-status

Get current scan progress.

**Response (200 OK):**
```json
{
  "data": {
    "scan_id": "scan-123",
    "status": "scanning",
    "current_phase": "vulnerability_detection",
    "phase_progress": 65,
    "phases": [
      { "name": "reconnaissance", "status": "completed", "completed_at": "..." },
      { "name": "crawling", "status": "completed", "completed_at": "..." },
      { "name": "vulnerability_detection", "status": "in_progress", "started_at": "..." },
      { "name": "exploitation_checks", "status": "pending" },
      { "name": "report_preparation", "status": "pending" }
    ],
    "estimated_time_remaining": 1200
  }
}
```

---

### GET /api/domains/{domain}/scan-history

Get scan history timeline.

**Response (200 OK):**
```json
{
  "data": [
    {
      "id": "scan-1",
      "started_at": "2026-01-15T10:00:00Z",
      "completed_at": "2026-01-15T11:00:00Z",
      "status": "completed",
      "duration": 3600,
      "findings_count": 8,
      "security_score": 72
    }
  ]
}
```

---

## Findings

### GET /api/domains/{domain}/findings

Fetch all findings for a domain.

**Query Parameters:**
- `severity` (optional): Filter by severity (critical|high|medium|low)
- `status` (optional): Filter by validation status
- `tool` (optional): Filter by scanning tool
- `per_page` (optional): Pagination (default: 50)

**Response (200 OK):**
```json
{
  "data": [
    {
      "id": "f1",
      "domain_id": "domain-1",
      "scan_id": "scan-1",
      "tool": "SQLMap",
      "url": "https://target.com/api/users?id=1",
      "payload": "' OR '1'='1",
      "vulnerability_name": "SQL Injection",
      "severity": "critical",
      "confidence": 95,
      "validation_status": "validated",
      "risk_status": "open",
      "retest_status": "pending",
      "notes": "Confirmed SQL injection",
      "first_seen_at": "2026-01-15T10:23:45Z",
      "sla_deadline": "2026-01-18T10:23:45Z",
      "owasp_category": "A03:2021-Injection",
      "cwe_id": "CWE-89",
      "cvss_score": 9.8,
      "description": "A SQL injection vulnerability...",
      "impact": "Complete database compromise...",
      "proof_of_concept": "curl command...",
      "remediation": "Use parameterized queries...",
      "references": ["https://owasp.org/..."]
    }
  ],
  "meta": {
    "current_page": 1,
    "last_page": 1,
    "per_page": 50,
    "total": 8
  }
}
```

---

### PATCH /api/domains/{domain}/findings/{finding}/validate

Update finding validation status.

**Request:**
```json
{
  "status": "validated",
  "notes": "Confirmed SQL injection vulnerability"
}
```

**Response (200 OK):** Returns updated finding object.

**Laravel Controller:**
```php
public function validate(Request $request, Domain $domain, Finding $finding)
{
    $validated = $request->validate([
        'status' => 'required|in:pending,validated,false_positive,needs_review',
        'notes' => 'nullable|string|max:5000',
    ]);

    $finding->update([
        'validation_status' => $validated['status'],
        'notes' => $validated['notes'] ?? $finding->notes,
        'validated_at' => now(),
        'validated_by' => auth()->id(),
    ]);

    // Recalculate domain security score
    $domain->recalculateSecurityScore();

    return new FindingResource($finding);
}
```

---

### PATCH /api/domains/{domain}/findings/batch-validate

Batch update multiple findings.

**Request:**
```json
{
  "finding_ids": ["f1", "f2", "f3"],
  "status": "validated"
}
```

**Response (200 OK):** Returns array of updated findings.

---

### PATCH /api/domains/{domain}/findings/{finding}/notes

Update finding notes only.

**Request:**
```json
{
  "notes": "Updated analyst notes"
}
```

---

### PATCH /api/domains/{domain}/findings/{finding}/risk-status

Update finding risk status.

**Request:**
```json
{
  "risk_status": "mitigated"
}
```

---

### POST /api/domains/{domain}/findings/{finding}/retest

Request a retest for a finding.

**Response (200 OK):**
```json
{
  "data": { "...finding with retest_status: pending..." },
  "message": "Retest requested"
}
```

---

## Analytics

### GET /api/domains/{domain}/score

Get domain security score.

**Response (200 OK):**
```json
{
  "score": 72,
  "breakdown": {
    "critical_impact": -40,
    "high_impact": -20,
    "medium_impact": -10,
    "low_impact": -4,
    "mitigated_bonus": 5,
    "validated_bonus": 10
  }
}
```

---

### GET /api/domains/{domain}/charts

Get chart data for analytics dashboard.

**Response (200 OK):**
```json
{
  "security_score": 72,
  "severity_distribution": [
    { "severity": "critical", "count": 2, "percentage": 25 },
    { "severity": "high", "count": 2, "percentage": 25 },
    { "severity": "medium", "count": 2, "percentage": 25 },
    { "severity": "low", "count": 2, "percentage": 25 }
  ],
  "validation_distribution": [
    { "status": "validated", "count": 4 },
    { "status": "false_positive", "count": 1 },
    { "status": "needs_review", "count": 1 },
    { "status": "pending", "count": 2 }
  ],
  "findings_trend": [
    { "date": "2026-01-10", "total": 12, "critical": 3, "high": 4, "medium": 3, "low": 2 },
    { "date": "2026-01-15", "total": 8, "critical": 2, "high": 2, "medium": 2, "low": 2 }
  ],
  "owasp_distribution": [
    { "category": "A01:2021-Broken Access Control", "short_name": "Access Control", "count": 2 },
    { "category": "A03:2021-Injection", "short_name": "Injection", "count": 3 }
  ],
  "risk_heatmap": [
    { "likelihood": "high", "impact": "high", "count": 2, "severity": "critical" }
  ]
}
```

---

## Reporting

### POST /api/domains/{domain}/reports

Generate VAPT report.

**Request:**
```json
{
  "include_validated": true,
  "include_false_positives": false,
  "include_needs_review": true,
  "format": "pdf"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "report_url": "/storage/reports/domain-1/vapt-report-2026-01-19.pdf",
  "message": "Report generated successfully"
}
```

---

## MySQL Schema

```sql
-- Users table
CREATE TABLE users (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    email_verified_at TIMESTAMP NULL,
    password VARCHAR(255) NOT NULL,
    role ENUM('admin', 'analyst', 'viewer') DEFAULT 'analyst',
    remember_token VARCHAR(100) NULL,
    created_at TIMESTAMP NULL,
    updated_at TIMESTAMP NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Domains table
CREATE TABLE domains (
    id VARCHAR(50) PRIMARY KEY,
    domain_name VARCHAR(255) NOT NULL UNIQUE,
    scan_status ENUM('queued', 'scanning', 'completed', 'failed') DEFAULT 'queued',
    current_phase ENUM('reconnaissance', 'crawling', 'vulnerability_detection', 'exploitation_checks', 'report_preparation', 'completed') NULL,
    phase_progress TINYINT UNSIGNED DEFAULT 0,
    security_score TINYINT UNSIGNED DEFAULT 0,
    last_scan_at TIMESTAMP NULL,
    created_at TIMESTAMP NULL,
    updated_at TIMESTAMP NULL,
    INDEX idx_scan_status (scan_status),
    INDEX idx_domain_name (domain_name)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Scans table
CREATE TABLE scans (
    id VARCHAR(50) PRIMARY KEY,
    domain_id VARCHAR(50) NOT NULL,
    status ENUM('queued', 'scanning', 'completed', 'failed') DEFAULT 'queued',
    current_phase ENUM('reconnaissance', 'crawling', 'vulnerability_detection', 'exploitation_checks', 'report_preparation', 'completed') NULL,
    phase_progress TINYINT UNSIGNED DEFAULT 0,
    tools_used JSON NULL,
    started_at TIMESTAMP NULL,
    completed_at TIMESTAMP NULL,
    duration INT UNSIGNED NULL,
    findings_count INT UNSIGNED DEFAULT 0,
    security_score TINYINT UNSIGNED DEFAULT 0,
    created_at TIMESTAMP NULL,
    updated_at TIMESTAMP NULL,
    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE,
    INDEX idx_domain_status (domain_id, status)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Findings table
CREATE TABLE findings (
    id VARCHAR(50) PRIMARY KEY,
    domain_id VARCHAR(50) NOT NULL,
    scan_id VARCHAR(50) NOT NULL,
    tool VARCHAR(100) NOT NULL,
    url TEXT NOT NULL,
    payload TEXT NULL,
    vulnerability_name VARCHAR(255) NOT NULL,
    severity ENUM('critical', 'high', 'medium', 'low') NOT NULL,
    confidence TINYINT UNSIGNED DEFAULT 0,
    validation_status ENUM('pending', 'validated', 'false_positive', 'needs_review') DEFAULT 'pending',
    risk_status ENUM('open', 'mitigated', 'accepted') DEFAULT 'open',
    retest_status ENUM('pending', 'passed', 'failed', 'not_required') DEFAULT 'pending',
    notes TEXT NULL,
    first_seen_at TIMESTAMP NOT NULL,
    sla_deadline TIMESTAMP NULL,
    owasp_category VARCHAR(100) NULL,
    cwe_id VARCHAR(20) NULL,
    cvss_score DECIMAL(3,1) NULL,
    description TEXT NULL,
    impact TEXT NULL,
    proof_of_concept TEXT NULL,
    remediation TEXT NULL,
    `references` JSON NULL,
    validated_at TIMESTAMP NULL,
    validated_by BIGINT UNSIGNED NULL,
    created_at TIMESTAMP NULL,
    updated_at TIMESTAMP NULL,
    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE,
    FOREIGN KEY (scan_id) REFERENCES scans(id) ON DELETE CASCADE,
    FOREIGN KEY (validated_by) REFERENCES users(id) ON SET NULL,
    INDEX idx_domain_severity (domain_id, severity),
    INDEX idx_domain_status (domain_id, validation_status),
    INDEX idx_sla_deadline (sla_deadline)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Reports table
CREATE TABLE reports (
    id BIGINT UNSIGNED AUTO_INCREMENT PRIMARY KEY,
    domain_id VARCHAR(50) NOT NULL,
    file_path VARCHAR(500) NOT NULL,
    format ENUM('pdf', 'docx') NOT NULL,
    include_validated BOOLEAN DEFAULT TRUE,
    include_false_positives BOOLEAN DEFAULT FALSE,
    include_needs_review BOOLEAN DEFAULT TRUE,
    generated_by BIGINT UNSIGNED NOT NULL,
    created_at TIMESTAMP NULL,
    FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE,
    FOREIGN KEY (generated_by) REFERENCES users(id)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
```

---

## Laravel Model Examples

### Domain Model

```php
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\HasMany;

class Domain extends Model
{
    public $incrementing = false;
    protected $keyType = 'string';

    protected $fillable = [
        'id',
        'domain_name',
        'scan_status',
        'current_phase',
        'phase_progress',
        'security_score',
        'last_scan_at',
    ];

    protected $casts = [
        'last_scan_at' => 'datetime',
        'phase_progress' => 'integer',
        'security_score' => 'integer',
    ];

    public function findings(): HasMany
    {
        return $this->hasMany(Finding::class);
    }

    public function scans(): HasMany
    {
        return $this->hasMany(Scan::class);
    }

    public function recalculateSecurityScore(): void
    {
        $score = 100;
        
        $findings = $this->findings()
            ->where('validation_status', '!=', 'false_positive')
            ->get();

        foreach ($findings as $finding) {
            $score -= match($finding->severity) {
                'critical' => 20,
                'high' => 10,
                'medium' => 5,
                'low' => 2,
                default => 0,
            };
        }

        $this->update(['security_score' => max(0, $score)]);
    }
}
```

### Finding Model

```php
<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class Finding extends Model
{
    public $incrementing = false;
    protected $keyType = 'string';

    protected $fillable = [
        'id',
        'domain_id',
        'scan_id',
        'tool',
        'url',
        'payload',
        'vulnerability_name',
        'severity',
        'confidence',
        'validation_status',
        'risk_status',
        'retest_status',
        'notes',
        'first_seen_at',
        'sla_deadline',
        'owasp_category',
        'cwe_id',
        'cvss_score',
        'description',
        'impact',
        'proof_of_concept',
        'remediation',
        'references',
        'validated_at',
        'validated_by',
    ];

    protected $casts = [
        'first_seen_at' => 'datetime',
        'sla_deadline' => 'datetime',
        'validated_at' => 'datetime',
        'references' => 'array',
        'confidence' => 'integer',
        'cvss_score' => 'decimal:1',
    ];

    public function domain(): BelongsTo
    {
        return $this->belongsTo(Domain::class);
    }

    public function scan(): BelongsTo
    {
        return $this->belongsTo(Scan::class);
    }

    public function validator(): BelongsTo
    {
        return $this->belongsTo(User::class, 'validated_by');
    }
}
```

---

## Laravel Routes

```php
// routes/api.php

use App\Http\Controllers\AuthController;
use App\Http\Controllers\DomainController;
use App\Http\Controllers\FindingController;
use App\Http\Controllers\ReportController;

// Public routes
Route::post('/login', [AuthController::class, 'login']);

// Protected routes
Route::middleware('auth:sanctum')->group(function () {
    Route::post('/logout', [AuthController::class, 'logout']);
    Route::get('/user', [AuthController::class, 'user']);

    // Domains
    Route::apiResource('domains', DomainController::class);
    Route::post('/domains/{domain}/scans', [DomainController::class, 'startScan']);
    Route::get('/domains/{domain}/scan-status', [DomainController::class, 'scanStatus']);
    Route::get('/domains/{domain}/scan-history', [DomainController::class, 'scanHistory']);
    Route::get('/domains/{domain}/score', [DomainController::class, 'score']);
    Route::get('/domains/{domain}/charts', [DomainController::class, 'charts']);

    // Findings
    Route::get('/domains/{domain}/findings', [FindingController::class, 'index']);
    Route::patch('/domains/{domain}/findings/{finding}/validate', [FindingController::class, 'validate']);
    Route::patch('/domains/{domain}/findings/batch-validate', [FindingController::class, 'batchValidate']);
    Route::patch('/domains/{domain}/findings/{finding}/notes', [FindingController::class, 'updateNotes']);
    Route::patch('/domains/{domain}/findings/{finding}/risk-status', [FindingController::class, 'updateRiskStatus']);
    Route::post('/domains/{domain}/findings/{finding}/retest', [FindingController::class, 'requestRetest']);

    // Reports
    Route::post('/domains/{domain}/reports', [ReportController::class, 'generate']);
});
```

---

## Environment Configuration

Add to your React app's `.env`:

```env
VITE_API_BASE_URL=http://localhost:8000
VITE_USE_MOCK_DATA=false
```

Add to your Laravel `.env`:

```env
SESSION_DRIVER=cookie
SANCTUM_STATEFUL_DOMAINS=localhost:5173,localhost:3000
SESSION_DOMAIN=localhost
```

---

## Integration Checklist

1. ✅ Install Laravel Sanctum
2. ✅ Configure CORS for SPA authentication
3. ✅ Run database migrations
4. ✅ Set `VITE_API_BASE_URL` in React `.env`
5. ✅ Set `VITE_USE_MOCK_DATA=false` in React `.env`
6. ✅ Ensure cookies are sent with `credentials: 'include'`
7. ✅ Handle CSRF token in request headers
