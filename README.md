# CodeScanner

A multi-tool security vulnerability scanner that combines 17 industry-standard static analysis tools with AI-powered code scanning using Google Gemini.

## Features

### SAST (Static Application Security Testing)
- **Bandit** - Python security linter
- **Semgrep** - Multi-language static analysis with security rulesets
- **ShellCheck** - Shell script static analysis
- **Gosec** - Go security checker
- **Brakeman** - Ruby on Rails security scanner
- **SpotBugs** - Java security scanner (with FindSecBugs)
- **PHPStan** - PHP static analyzer
- **Horusec** - Multi-language SAST tool

### Secrets Detection
- **Gitleaks** - Secrets detection scanner
- **TruffleHog** - Git history secrets scanner
- **detect-secrets** - Yelp's secrets detection tool

### Dependency Scanning
- **Safety** - Python dependency vulnerability checker
- **Grype** - Multi-language dependency scanner
- **Trivy** - Comprehensive vulnerability scanner

### Infrastructure as Code
- **Checkov** - IaC security scanner (Terraform, CloudFormation, Kubernetes)
- **Hadolint** - Dockerfile linter and best practices

### AI Analysis
- **Gemini AI** - AI-powered code analysis using Gemini 2.5 Pro or 3 Pro

### Additional Features
- **Professional GUI** - Dark-themed interface with collapsible engine categories
- **Multiple Export Formats** - Markdown, HTML, JSON reports
- **CWE/OWASP Mapping** - Industry-standard vulnerability classification

## Requirements

- Python 3.11+
- Gemini API key (optional, for AI scanning)

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/codescanner.git
cd codescanner
```

### 2. Create a virtual environment

**Windows:**
```bash
python -m venv .venv
.venv\Scripts\activate
```

**macOS/Linux:**
```bash
python3 -m venv .venv
source .venv/bin/activate
```

### 3. Install Python dependencies

```bash
pip install -r requirements.txt
```

### 4. Install external tools (optional)

For full scanning capabilities, install the external tools below. The scanner will automatically detect which tools are available and skip those that aren't installed.

#### Python-based tools (installed via pip)

These are included in `requirements.txt` and installed automatically:
- **Bandit** - Python security linter
- **Semgrep** - Multi-language static analysis
- **Safety** - Python dependency checker
- **detect-secrets** - Secrets detection
- **Checkov** - Infrastructure as Code scanner

#### Windows Installation

**Using Chocolatey (requires admin):**
```powershell
# Secrets detection
choco install gitleaks
choco install trufflehog

# Vulnerability scanning
choco install trivy
choco install grype

# IaC/Container
choco install hadolint
choco install shellcheck
```

**Using winget:**
```powershell
winget install Gitleaks.Gitleaks
winget install aquasecurity.trivy
```

**Manual Downloads:**
- [Gitleaks](https://github.com/gitleaks/gitleaks/releases) - Download `gitleaks_*_windows_amd64.zip`
- [TruffleHog](https://github.com/trufflesecurity/trufflehog/releases) - Download `trufflehog_*_windows_amd64.tar.gz`
- [Trivy](https://github.com/aquasecurity/trivy/releases) - Download `trivy_*_Windows-64bit.zip`
- [Grype](https://github.com/anchore/grype/releases) - Download `grype_*_windows_amd64.zip`
- [Hadolint](https://github.com/hadolint/hadolint/releases) - Download `hadolint-Windows-x86_64.exe`
- [ShellCheck](https://github.com/koalaman/shellcheck/releases) - Download `shellcheck-*.zip`
- [Horusec](https://github.com/ZupIT/horusec/releases) - Download `horusec_*_windows_amd64.zip`

Extract and add to your PATH, or place in the project directory.

#### Linux Installation

**Using apt (Debian/Ubuntu):**
```bash
# ShellCheck
sudo apt install shellcheck

# Hadolint
wget -qO /usr/local/bin/hadolint https://github.com/hadolint/hadolint/releases/latest/download/hadolint-Linux-x86_64
sudo chmod +x /usr/local/bin/hadolint
```

**Using Homebrew (Linux/macOS):**
```bash
brew install gitleaks
brew install trufflehog
brew install trivy
brew install grype
brew install hadolint
brew install shellcheck
brew install horusec
```

**Using install scripts:**
```bash
# Gitleaks
curl -sSfL https://github.com/gitleaks/gitleaks/releases/latest/download/gitleaks_*_linux_x64.tar.gz | tar xz
sudo mv gitleaks /usr/local/bin/

# TruffleHog
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b /usr/local/bin

# Trivy
curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh | sh -s -- -b /usr/local/bin

# Grype
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sh -s -- -b /usr/local/bin

# Horusec
curl -fsSL https://raw.githubusercontent.com/ZupIT/horusec/main/deployments/scripts/install.sh | bash -s latest
```

#### Language-Specific Tools

**Go (Gosec):**
```bash
# Requires Go 1.20+
go install github.com/securego/gosec/v2/cmd/gosec@latest
```

**Ruby (Brakeman):**
```bash
# Requires Ruby 2.7+
gem install brakeman
```

**Java (SpotBugs):**
```bash
# Download from https://spotbugs.github.io/
# Or use Maven/Gradle plugin

# Linux/macOS
wget https://github.com/spotbugs/spotbugs/releases/download/4.8.3/spotbugs-4.8.3.tgz
tar xzf spotbugs-4.8.3.tgz
export PATH=$PATH:$(pwd)/spotbugs-4.8.3/bin
```

**PHP (PHPStan):**
```bash
# Requires PHP 7.4+ and Composer
composer global require phpstan/phpstan

# Or per-project
composer require --dev phpstan/phpstan
```

#### Verifying Installation

Run the scanner to see which tools are detected:
```bash
python main.py scan ./your-project
```

The scanner will show `[tool] not available` for missing tools and continue with available engines

## Usage

### GUI Mode

Launch the graphical interface:

```bash
python main.py gui
```

1. Select a target directory to scan
2. Expand/collapse engine categories to enable/disable scanners
3. Use "All" / "None" buttons for quick selection
4. Enter your Gemini API key for AI scanning (optional)
5. Click "Start Scan"
6. Export results as Markdown, HTML, or JSON

### CLI Mode

Run a scan from the command line:

```bash
# Basic scan with all available engines
python main.py scan ./your-project

# Save report to file
python main.py scan ./your-project -o report.md

# Enable AI scanning with Gemini
python main.py scan ./your-project --api-key YOUR_GEMINI_API_KEY

# Disable specific engines
python main.py scan ./your-project --no-bandit --no-semgrep
```

### CLI Options

| Option | Description |
|--------|-------------|
| `-o, --output` | Output file path (.md, .html, .json) |
| `--api-key` | Gemini API key for AI scanning |
| `--no-bandit` | Disable Bandit |
| `--no-semgrep` | Disable Semgrep |
| `--no-safety` | Disable Safety |
| `--no-gemini` | Disable Gemini AI |
| `--no-gitleaks` | Disable Gitleaks |
| `--no-trufflehog` | Disable TruffleHog |
| `--no-detect-secrets` | Disable detect-secrets |
| `--no-trivy` | Disable Trivy |
| `--no-grype` | Disable Grype |
| `--no-checkov` | Disable Checkov |
| `--no-shellcheck` | Disable ShellCheck |
| `--no-hadolint` | Disable Hadolint |
| `--no-gosec` | Disable Gosec |
| `--no-brakeman` | Disable Brakeman |
| `--no-spotbugs` | Disable SpotBugs |
| `--no-phpstan` | Disable PHPStan |
| `--no-horusec` | Disable Horusec |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `GEMINI_API_KEY` | Gemini API key (auto-loaded in GUI) |

## Supported Languages

| Engine | Languages / Targets |
|--------|---------------------|
| Bandit | Python |
| Semgrep | Python, JavaScript, TypeScript, Java, Go, Ruby, PHP, C, C++ |
| ShellCheck | Bash, Shell scripts |
| Gosec | Go |
| Brakeman | Ruby on Rails |
| SpotBugs | Java |
| PHPStan | PHP |
| Horusec | Go, Python, JavaScript, Java, Kotlin, Ruby, PHP, C#, and more |
| Gitleaks | All (secrets in any file) |
| TruffleHog | All (git history secrets) |
| detect-secrets | All (secrets detection) |
| Safety | Python dependencies |
| Grype | Multi-language dependencies |
| Trivy | Containers, filesystems, dependencies |
| Checkov | Terraform, CloudFormation, Kubernetes, Dockerfile |
| Hadolint | Dockerfile |
| Gemini AI | All languages |

## Project Structure

```
codescanner/
├── main.py                 # CLI/GUI entry point
├── requirements.txt        # Python dependencies
├── pyproject.toml          # Project configuration
└── src/
    ├── scanner/
    │   ├── engine.py       # Main scanner orchestrator
    │   ├── models.py       # Finding, Severity, ScanResult
    │   ├── report.py       # Report generator (MD/HTML/JSON)
    │   └── engines/
    │       ├── bandit_engine.py
    │       ├── semgrep_engine.py
    │       ├── safety_engine.py
    │       ├── gemini_engine.py
    │       ├── gitleaks_engine.py
    │       ├── trufflehog_engine.py
    │       ├── detect_secrets_engine.py
    │       ├── trivy_engine.py
    │       ├── grype_engine.py
    │       ├── checkov_engine.py
    │       ├── shellcheck_engine.py
    │       ├── hadolint_engine.py
    │       ├── gosec_engine.py
    │       ├── brakeman_engine.py
    │       ├── spotbugs_engine.py
    │       ├── phpstan_engine.py
    │       └── horusec_engine.py
    └── gui/
        └── app.py          # CustomTkinter GUI
```

## Report Output

Reports include:
- Executive summary with risk level
- Findings grouped by severity (Critical, High, Medium, Low, Info)
- CWE and OWASP category mappings
- Code snippets with line numbers
- Remediation recommendations
- Statistics by tool and vulnerability type

## License

MIT License
