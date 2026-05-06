# CVEBox

Security scanner CLI for web applications — QA Edition.

Pattern-based vulnerability scanner with Playwright. Tests for SQL Injection, NoSQL Injection, XSS, SSTI, and Prototype Pollution. Generates HTML reports with CVE references.

---

## Requirements

- Node.js 18+
- Yarn

---

## Installation

```bash
git clone https://github.com/lrbg/CVEBox.git
cd CVEBox
yarn install
npx playwright install chromium
cp .env.example .env
# Edit .env with your target URLs and credentials
```

---

## Configuration (.env)

```env
TARGET_NAME=My App
TARGET_URL=https://yourapp.com/dashboard
TARGET_LOGIN_URL=https://yourapp.com/login
TARGET_USERNAME=your@email.com
TARGET_PASSWORD=yourpassword

BROWSER_HEADED=false
SCAN_TIMEOUT_MS=8000
REPORTS_DIR=./reports
```

To scan **multiple applications**, add a second target:

```env
TARGET_2_NAME=Another App
TARGET_2_URL=https://anotherapp.com
TARGET_2_LOGIN_URL=https://anotherapp.com/login
TARGET_2_USERNAME=user@another.com
TARGET_2_PASSWORD=pass456
```

---

## Usage

### Interactive mode (manual QA)

```bash
yarn start
```

The CLI will show a menu:
1. Select tests to run (or run all)
2. Select attack surfaces (forms, query params, headers, API body)
3. Choose headed/headless browser
4. Report is generated automatically in `./reports/`

### Pipeline mode (CI/CD — AzDo, Jenkins, GitHub Actions)

```bash
# Run all tests
yarn start --pipeline

# Run specific tests
yarn start --pipeline --plugins sql-injection,xss --surfaces form,query-param

# Run headed (visible browser)
yarn start --pipeline --headed
```

---

## Plugin IDs

| Plugin ID              | Description                                      |
|------------------------|--------------------------------------------------|
| `sql-injection`        | SQL Injection (MySQL, PostgreSQL, SQL Server, Oracle) |
| `nosql-injection`      | NoSQL Injection (MongoDB operator injection)     |
| `xss`                  | XSS — Reflected, Stored, DOM-based              |
| `ssti`                 | Server-Side Template Injection                   |
| `prototype-pollution`  | JavaScript Prototype Pollution                   |

---

## Surface IDs

| Surface ID    | Description                              |
|---------------|------------------------------------------|
| `form`        | HTML form input fields                   |
| `query-param` | URL query string parameters (GET)        |
| `header`      | HTTP request headers                     |
| `api-body`    | JSON body in POST/PUT/PATCH API calls    |

---

## Adding Custom Payloads

Edit any file under `src/patterns/`:

```json
[
  {
    "value": "your-payload-here",
    "description": "What this payload tests",
    "cveId": "CVE-2024-XXXXX",
    "cveUrl": "https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-XXXXX",
    "severity": "high",
    "dbTarget": "mysql"
  }
]
```

---

## CI/CD Integration

### GitHub Actions

```yaml
- name: Run CVEBox Security Scan
  run: yarn start --pipeline --plugins sql-injection,xss --surfaces form,query-param
  env:
    TARGET_URL: ${{ secrets.TARGET_URL }}
    TARGET_LOGIN_URL: ${{ secrets.TARGET_LOGIN_URL }}
    TARGET_USERNAME: ${{ secrets.TARGET_USERNAME }}
    TARGET_PASSWORD: ${{ secrets.TARGET_PASSWORD }}

- name: Upload Security Report
  uses: actions/upload-artifact@v4
  with:
    name: cvebox-report
    path: reports/
```

### Azure DevOps

```yaml
- script: yarn start --pipeline
  displayName: 'CVEBox Security Scan'
  env:
    TARGET_URL: $(TARGET_URL)
    TARGET_LOGIN_URL: $(TARGET_LOGIN_URL)
    TARGET_USERNAME: $(TARGET_USERNAME)
    TARGET_PASSWORD: $(TARGET_PASSWORD)

- task: PublishBuildArtifacts@1
  inputs:
    pathToPublish: 'reports'
    artifactName: 'security-reports'
```

---

## Report

Each scan generates one HTML file per target in `./reports/`. The report includes:

- Severity badge (Critical / High / Medium)
- CVE/CWE reference ID with direct link
- Injected payload
- Evidence (what was detected)
- Recommended fix

---

## Adding a New Plugin

1. Create `src/plugins/my-plugin.plugin.ts` extending `BasePlugin`
2. Add payload patterns to `src/patterns/my-plugin/payloads.json`
3. Register in `src/plugins/registry.ts`
4. Add the plugin ID to `src/types/index.ts` → `PluginId`
