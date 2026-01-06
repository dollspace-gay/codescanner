# Python Development Standards

## Code Formatting

### Formatter: Black
- Line length: 88 characters (Black default)
- Use `black .` to format all files
- Configure in `pyproject.toml`:
```toml
[tool.black]
line-length = 88
target-version = ['py311']
```

### Import Sorting: isort
- Black-compatible profile
- Configure in `pyproject.toml`:
```toml
[tool.isort]
profile = "black"
line_length = 88
```

## Linting

### Ruff (Primary Linter)
Fast, comprehensive linter replacing flake8, pylint, and more.

```toml
[tool.ruff]
line-length = 88
target-version = "py311"

[tool.ruff.lint]
select = [
    "E",      # pycodestyle errors
    "W",      # pycodestyle warnings
    "F",      # Pyflakes
    "I",      # isort
    "B",      # flake8-bugbear
    "C4",     # flake8-comprehensions
    "UP",     # pyupgrade
    "S",      # flake8-bandit (security)
    "SIM",    # flake8-simplify
    "RUF",    # Ruff-specific rules
]
ignore = ["E501"]  # line length handled by formatter
```

### Type Checking: mypy
```toml
[tool.mypy]
python_version = "3.11"
strict = true
warn_return_any = true
warn_unused_ignores = true
disallow_untyped_defs = true
```

## Security Best Practices

### Input Validation
- Never trust user input
- Validate types, ranges, and formats explicitly
- Use Pydantic models for structured input validation

### SQL Injection Prevention
```python
# WRONG - vulnerable
cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")

# CORRECT - parameterized query
cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
```

### Command Injection Prevention
```python
# WRONG - vulnerable
os.system(f"echo {user_input}")

# CORRECT - use subprocess with list args
subprocess.run(["echo", user_input], shell=False)
```

### Secrets Management
- Never hardcode secrets, API keys, or passwords
- Use environment variables or secret managers
- Add `.env` to `.gitignore`
- Use `python-dotenv` for local development

### Dependency Security
- Pin dependencies with exact versions in `requirements.txt`
- Run `pip-audit` or `safety check` regularly
- Keep dependencies updated

### Path Traversal Prevention
```python
# WRONG - vulnerable
open(os.path.join(base_dir, user_filename))

# CORRECT - validate path stays within base
resolved = os.path.realpath(os.path.join(base_dir, user_filename))
if not resolved.startswith(os.path.realpath(base_dir)):
    raise ValueError("Invalid path")
```

### Sensitive Data Handling
- Never log passwords, tokens, or PII
- Use `secrets` module for cryptographic randomness
- Hash passwords with `bcrypt` or `argon2`

## Code Quality Rules

### No Stubs or Incomplete Code
- Never write `TODO`, `FIXME`, `pass` as placeholders
- Complete all function implementations
- If too complex: raise `NotImplementedError` with reason

### Error Handling
```python
# Catch specific exceptions, not bare except
try:
    result = risky_operation()
except ValueError as e:
    logger.error("Invalid value: %s", e)
    raise
except ConnectionError as e:
    logger.error("Connection failed: %s", e)
    return None
```

### Logging
- Use `logging` module, not `print()`
- Include context in log messages
- Use appropriate log levels (DEBUG, INFO, WARNING, ERROR)

### Type Hints
- Add type hints to all function signatures
- Use `typing` module for complex types
- Run mypy in strict mode

## Pre-commit Configuration

```yaml
# .pre-commit-config.yaml
repos:
  - repo: https://github.com/astral-sh/ruff-pre-commit
    rev: v0.4.4
    hooks:
      - id: ruff
        args: [--fix]
      - id: ruff-format
  - repo: https://github.com/pre-commit/mirrors-mypy
    rev: v1.10.0
    hooks:
      - id: mypy
        additional_dependencies: []
```

## Project Structure

```
project/
├── src/
│   └── package_name/
│       ├── __init__.py
│       └── module.py
├── tests/
│   └── test_module.py
├── pyproject.toml
├── requirements.txt
└── .pre-commit-config.yaml
```
