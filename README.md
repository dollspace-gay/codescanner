# CodeScanner

A multi-tool security vulnerability scanner that combines industry-standard static analysis tools with AI-powered code scanning using Google Gemini.

## Features

- **Bandit** - Python security linter (SQL injection, hardcoded passwords, etc.)
- **Semgrep** - Multi-language static analysis with security rulesets
- **Safety** - Python dependency vulnerability checker
- **Gemini AI** - AI-powered code analysis using Gemini 2.5 Pro or 3 Pro
- **Professional GUI** - Dark-themed interface with real-time progress
- **Multiple Export Formats** - Markdown, HTML, JSON reports

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

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Verify installation

```bash
python -c "from src.scanner.engines import BanditEngine, SemgrepEngine, SafetyEngine; print('All engines installed successfully')"
```

## Usage

### GUI Mode

Launch the graphical interface:

```bash
python main.py gui
```

1. Select a target directory to scan
2. Enable/disable scanner engines as needed
3. Enter your Gemini API key for AI scanning (optional)
4. Select Gemini model (2.5 Pro or 3 Pro)
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
| `--no-bandit` | Disable Bandit engine |
| `--no-semgrep` | Disable Semgrep engine |
| `--no-safety` | Disable Safety engine |
| `--no-gemini` | Disable Gemini AI engine |

## Environment Variables

| Variable | Description |
|----------|-------------|
| `GEMINI_API_KEY` | Gemini API key (auto-loaded in GUI) |

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
    │       └── gemini_engine.py
    └── gui/
        └── app.py          # CustomTkinter GUI
```

## Supported Languages

The scanner supports multiple languages depending on the engine:

| Engine | Languages |
|--------|-----------|
| Bandit | Python |
| Semgrep | Python, JavaScript, TypeScript, Java, Go, Ruby, PHP, C, C++, and more |
| Safety | Python (dependencies) |
| Gemini AI | All languages |

## Report Output

Reports include:
- Executive summary with risk level
- Findings grouped by severity (Critical, High, Medium, Low, Info)
- CWE and OWASP category mappings
- Code snippets with line numbers
- Remediation recommendations

## License

MIT License
