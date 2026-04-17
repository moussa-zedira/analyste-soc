"""DevSecOps CI/CD Security Scanner Engine.

Provides SAST, DAST, SCA, Secret Detection, Container Security, and IaC scanning.
"""

from __future__ import annotations

import asyncio
import datetime as _dt
import hashlib
import json
import logging
import os
import re
import uuid
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Optional

import httpx
import structlog

from apps.api.devsecops import scanner_engines as _engines

logger = logging.getLogger(__name__)
slog = structlog.get_logger(__name__)


def _normalize_findings(items: list) -> list[dict]:
    """Convert ScanFindingResult instances or dicts to a unified dict shape that
    works with both ``ScanFindingResult.to_dict()`` consumers and the
    ``apps.api.routes.devsecops._persist_run`` writer (which reads ``file``/``line``).
    """
    out: list[dict] = []
    for it in items:
        if isinstance(it, dict):
            d = dict(it)
        elif hasattr(it, "to_dict"):
            d = it.to_dict()
        else:
            continue
        # Aliases so _persist_run finds 'file' and 'line'
        if "file" not in d:
            d["file"] = d.get("file_path", "") or ""
        if "file_path" not in d:
            d["file_path"] = d.get("file", "") or ""
        if "line" not in d:
            d["line"] = d.get("line_number", 0) or 0
        if "line_number" not in d:
            d["line_number"] = d.get("line", 0) or 0
        out.append(d)
    return out

# ═══════════════════════════════════════════════════════════════════════════════
# DATA STRUCTURES
# ═══════════════════════════════════════════════════════════════════════════════


@dataclass
class ScanFindingResult:
    """A single security finding."""

    title: str
    severity: str  # critical, high, medium, low, info
    scan_type: str  # sast, sca, secrets, dast, container, iac
    description: str = ""
    cwe_id: str = ""
    file_path: str = ""
    line_number: int = 0
    code_snippet: str = ""
    remediation: str = ""
    raw_data: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return asdict(self)


# ═══════════════════════════════════════════════════════════════════════════════
# SAST — STATIC APPLICATION SECURITY TESTING
# ═══════════════════════════════════════════════════════════════════════════════

# -- Python patterns --
_PYTHON_RULES: list[dict] = [
    {
        "pattern": re.compile(r"\beval\s*\("),
        "title": "Use of eval()",
        "severity": "high",
        "cwe": "CWE-95",
        "description": "eval() can execute arbitrary code if input is user-controlled.",
        "remediation": "Use ast.literal_eval() for safe evaluation of literals, or refactor to avoid eval entirely.",
    },
    {
        "pattern": re.compile(r"\bexec\s*\("),
        "title": "Use of exec()",
        "severity": "high",
        "cwe": "CWE-95",
        "description": "exec() can execute arbitrary code if input is user-controlled.",
        "remediation": "Avoid exec(). Use a whitelist-based approach or sandboxed environment.",
    },
    {
        "pattern": re.compile(r"subprocess\.\w+\(.*shell\s*=\s*True", re.DOTALL),
        "title": "subprocess with shell=True",
        "severity": "high",
        "cwe": "CWE-78",
        "description": "shell=True allows shell injection if arguments include user input.",
        "remediation": "Use shell=False (default) and pass arguments as a list.",
    },
    {
        "pattern": re.compile(r"""(?:execute|cursor\.execute)\s*\(\s*(?:f['\"]|['\"].*%s|.*\.format\()"""),
        "title": "SQL string concatenation/formatting",
        "severity": "critical",
        "cwe": "CWE-89",
        "description": "Building SQL queries via string formatting allows SQL injection.",
        "remediation": "Use parameterized queries with placeholders (?, %s) and parameter tuples.",
    },
    {
        "pattern": re.compile(r"pickle\.loads?\s*\("),
        "title": "Unsafe pickle deserialization",
        "severity": "critical",
        "cwe": "CWE-502",
        "description": "pickle.load/loads can execute arbitrary code during deserialization.",
        "remediation": "Use json or another safe serialization format. If pickle is required, use hmac signing.",
    },
    {
        "pattern": re.compile(r"yaml\.load\s*\([^)]*\)(?!.*Loader\s*=\s*(?:Safe|Base))"),
        "title": "yaml.load without SafeLoader",
        "severity": "high",
        "cwe": "CWE-502",
        "description": "yaml.load() without SafeLoader can execute arbitrary Python objects.",
        "remediation": "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader).",
    },
    {
        "pattern": re.compile(r"(?:password|secret|token|api_key)\s*=\s*['\"][^'\"]{4,}['\"]", re.IGNORECASE),
        "title": "Hardcoded secret in Python source",
        "severity": "high",
        "cwe": "CWE-798",
        "description": "Hardcoded credentials or secrets found in source code.",
        "remediation": "Use environment variables or a secrets manager (Vault, AWS Secrets Manager).",
    },
    {
        "pattern": re.compile(r"__import__\s*\("),
        "title": "Dynamic import via __import__()",
        "severity": "medium",
        "cwe": "CWE-95",
        "description": "__import__() with user input can load arbitrary modules.",
        "remediation": "Use importlib with a whitelist of allowed modules.",
    },
    {
        "pattern": re.compile(r"os\.system\s*\("),
        "title": "Use of os.system()",
        "severity": "high",
        "cwe": "CWE-78",
        "description": "os.system() is vulnerable to command injection.",
        "remediation": "Use subprocess.run() with shell=False and argument list.",
    },
    {
        "pattern": re.compile(r"tempfile\.mktemp\s*\("),
        "title": "Insecure temp file creation",
        "severity": "medium",
        "cwe": "CWE-377",
        "description": "tempfile.mktemp() is vulnerable to race conditions.",
        "remediation": "Use tempfile.mkstemp() or tempfile.NamedTemporaryFile().",
    },
]

# -- JavaScript / TypeScript patterns --
_JS_RULES: list[dict] = [
    {
        "pattern": re.compile(r"\.innerHTML\s*="),
        "title": "innerHTML assignment (XSS risk)",
        "severity": "high",
        "cwe": "CWE-79",
        "description": "Setting innerHTML with unsanitized input enables XSS.",
        "remediation": "Use textContent or a sanitization library (DOMPurify).",
    },
    {
        "pattern": re.compile(r"document\.write\s*\("),
        "title": "document.write() usage",
        "severity": "high",
        "cwe": "CWE-79",
        "description": "document.write() with user input enables XSS attacks.",
        "remediation": "Use DOM manipulation methods (createElement, appendChild).",
    },
    {
        "pattern": re.compile(r"\beval\s*\("),
        "title": "eval() in JavaScript",
        "severity": "critical",
        "cwe": "CWE-95",
        "description": "eval() executes arbitrary JavaScript code.",
        "remediation": "Use JSON.parse() for data, Function constructor sparingly, or refactor.",
    },
    {
        "pattern": re.compile(r"dangerouslySetInnerHTML"),
        "title": "React dangerouslySetInnerHTML",
        "severity": "high",
        "cwe": "CWE-79",
        "description": "dangerouslySetInnerHTML can introduce XSS if input is not sanitized.",
        "remediation": "Sanitize HTML with DOMPurify before passing to dangerouslySetInnerHTML.",
    },
    {
        "pattern": re.compile(r"\.__proto__\s*[=\[]|Object\.assign\s*\(\s*\{\}"),
        "title": "Prototype pollution pattern",
        "severity": "high",
        "cwe": "CWE-1321",
        "description": "Direct __proto__ access or unsafe Object.assign can lead to prototype pollution.",
        "remediation": "Use Object.create(null) for dictionaries, validate keys, use Map instead of objects.",
    },
    {
        "pattern": re.compile(r"new\s+RegExp\s*\([^)]*\+"),
        "title": "RegExp DoS (ReDoS) risk",
        "severity": "medium",
        "cwe": "CWE-1333",
        "description": "Dynamic RegExp with user input can cause catastrophic backtracking.",
        "remediation": "Use a regex complexity analyzer or escape user input with escapeRegExp().",
    },
    {
        "pattern": re.compile(r"(?:localStorage|sessionStorage)\.(?:setItem|getItem)\s*\(.*(?:password|token|secret)", re.IGNORECASE),
        "title": "Sensitive data in browser storage",
        "severity": "medium",
        "cwe": "CWE-922",
        "description": "Storing secrets in localStorage/sessionStorage is accessible to XSS.",
        "remediation": "Use httpOnly secure cookies for sensitive tokens.",
    },
    {
        "pattern": re.compile(r"child_process\.\s*exec\s*\("),
        "title": "child_process.exec() command injection",
        "severity": "critical",
        "cwe": "CWE-78",
        "description": "child_process.exec() passes input through shell, enabling injection.",
        "remediation": "Use child_process.execFile() or spawn() with argument arrays.",
    },
]

# -- Java patterns --
_JAVA_RULES: list[dict] = [
    {
        "pattern": re.compile(r"Runtime\.getRuntime\(\)\.exec\s*\("),
        "title": "Runtime.exec() command execution",
        "severity": "critical",
        "cwe": "CWE-78",
        "description": "Runtime.exec() can execute system commands; vulnerable if input is user-controlled.",
        "remediation": "Validate and sanitize input. Use ProcessBuilder with argument list.",
    },
    {
        "pattern": re.compile(r"""(?:executeQuery|executeUpdate|prepareStatement)\s*\(\s*(?:.*\+\s*|.*String\.format)"""),
        "title": "SQL concatenation in Java",
        "severity": "critical",
        "cwe": "CWE-89",
        "description": "Building SQL via string concatenation enables SQL injection.",
        "remediation": "Use PreparedStatement with parameterized queries.",
    },
    {
        "pattern": re.compile(r"XMLInputFactory|DocumentBuilderFactory|SAXParserFactory"),
        "title": "Potential XXE vulnerability",
        "severity": "high",
        "cwe": "CWE-611",
        "description": "XML parsers without external entity protection are vulnerable to XXE.",
        "remediation": "Disable external entities: factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true).",
    },
    {
        "pattern": re.compile(r"ObjectInputStream\s*\("),
        "title": "Java deserialization risk",
        "severity": "critical",
        "cwe": "CWE-502",
        "description": "ObjectInputStream can deserialize malicious payloads leading to RCE.",
        "remediation": "Use a look-ahead deserialization filter or switch to JSON/protobuf.",
    },
    {
        "pattern": re.compile(r"(?:MD5|SHA1)(?:Digest|\.getInstance)"),
        "title": "Weak hashing algorithm",
        "severity": "medium",
        "cwe": "CWE-328",
        "description": "MD5 and SHA-1 are cryptographically broken.",
        "remediation": "Use SHA-256 or SHA-3 for hashing.",
    },
]

# -- Go patterns --
_GO_RULES: list[dict] = [
    {
        "pattern": re.compile(r'(?:db\.Query|db\.Exec)\s*\(\s*(?:.*\+|fmt\.Sprintf)'),
        "title": "SQL query with string concatenation in Go",
        "severity": "critical",
        "cwe": "CWE-89",
        "description": "SQL queries built via string concatenation are vulnerable to SQL injection.",
        "remediation": "Use parameterized queries: db.Query(\"SELECT * FROM t WHERE id = ?\", id).",
    },
    {
        "pattern": re.compile(r'"math/rand"'),
        "title": "math/rand for security-sensitive operations",
        "severity": "medium",
        "cwe": "CWE-338",
        "description": "math/rand is not cryptographically secure.",
        "remediation": 'Use "crypto/rand" for security-sensitive random number generation.',
    },
    {
        "pattern": re.compile(r'(?:password|secret|token|apiKey)\s*(?::=|=)\s*"[^"]{4,}"', re.IGNORECASE),
        "title": "Hardcoded credentials in Go source",
        "severity": "high",
        "cwe": "CWE-798",
        "description": "Hardcoded credentials found in source code.",
        "remediation": "Use environment variables or a secrets manager.",
    },
    {
        "pattern": re.compile(r"template\.HTML\s*\("),
        "title": "Unescaped HTML template output",
        "severity": "high",
        "cwe": "CWE-79",
        "description": "template.HTML() marks content as safe, bypassing auto-escaping.",
        "remediation": "Let Go html/template auto-escape; only use template.HTML for trusted content.",
    },
]

# -- PHP patterns --
_PHP_RULES: list[dict] = [
    {
        "pattern": re.compile(r"\b(?:system|passthru|shell_exec|popen|proc_open)\s*\("),
        "title": "PHP command execution function",
        "severity": "critical",
        "cwe": "CWE-78",
        "description": "Direct OS command execution via PHP function.",
        "remediation": "Use escapeshellarg()/escapeshellcmd() or avoid shell commands entirely.",
    },
    {
        "pattern": re.compile(r"\bexec\s*\("),
        "title": "PHP exec() usage",
        "severity": "critical",
        "cwe": "CWE-78",
        "description": "exec() executes system commands; vulnerable to injection.",
        "remediation": "Sanitize inputs with escapeshellarg() or use safer alternatives.",
    },
    {
        "pattern": re.compile(r"\b(?:include|require|include_once|require_once)\s*\(\s*\$"),
        "title": "PHP file inclusion with variable",
        "severity": "critical",
        "cwe": "CWE-98",
        "description": "Dynamic file inclusion with user-controlled variable enables LFI/RFI.",
        "remediation": "Use a whitelist of allowed files. Never use user input directly in include.",
    },
    {
        "pattern": re.compile(r'(?:mysql_query|mysqli_query)\s*\(\s*.*\.\s*\$'),
        "title": "PHP SQL concatenation",
        "severity": "critical",
        "cwe": "CWE-89",
        "description": "SQL queries built with concatenated variables enable SQL injection.",
        "remediation": "Use PDO prepared statements with parameterized queries.",
    },
    {
        "pattern": re.compile(r"\bunserialize\s*\("),
        "title": "PHP unserialize() usage",
        "severity": "high",
        "cwe": "CWE-502",
        "description": "unserialize() with untrusted data can lead to object injection.",
        "remediation": "Use json_decode() or specify allowed_classes parameter.",
    },
]

# -- Language to extension mapping --
_LANG_EXT_MAP: dict[str, tuple[str, ...]] = {
    "python": (".py",),
    "javascript": (".js", ".jsx", ".mjs"),
    "typescript": (".ts", ".tsx"),
    "java": (".java",),
    "go": (".go",),
    "php": (".php",),
}

_EXT_TO_RULES: dict[str, list[dict]] = {
    ".py": _PYTHON_RULES,
    ".js": _JS_RULES,
    ".jsx": _JS_RULES,
    ".mjs": _JS_RULES,
    ".ts": _JS_RULES,
    ".tsx": _JS_RULES,
    ".java": _JAVA_RULES,
    ".go": _GO_RULES,
    ".php": _PHP_RULES,
}

# -- Generic secret patterns applied to ALL file types --
_GENERIC_SECRET_PATTERNS: list[dict] = [
    {
        "pattern": re.compile(r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}"),
        "title": "AWS Access Key ID",
        "severity": "critical",
        "cwe": "CWE-798",
    },
    {
        "pattern": re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}"),
        "title": "GitHub Personal Access Token",
        "severity": "critical",
        "cwe": "CWE-798",
    },
    {
        "pattern": re.compile(r"glpat-[A-Za-z0-9\-_]{20,}"),
        "title": "GitLab Personal Access Token",
        "severity": "critical",
        "cwe": "CWE-798",
    },
    {
        "pattern": re.compile(r"xox[bpsar]-[A-Za-z0-9\-]{10,}"),
        "title": "Slack Token",
        "severity": "critical",
        "cwe": "CWE-798",
    },
    {
        "pattern": re.compile(r"sk-[A-Za-z0-9]{20,}"),
        "title": "OpenAI / Stripe Secret Key",
        "severity": "critical",
        "cwe": "CWE-798",
    },
]


async def _run_sast_regex(
    path: str,
    languages: list[str] | None = None,
    exclude_dirs: list[str] | None = None,
) -> list[ScanFindingResult]:
    """Run SAST scan on a local directory or file (regex-based fallback)."""
    findings: list[ScanFindingResult] = []
    target = Path(path)
    exclude = set(exclude_dirs or [".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"])

    if target.is_file():
        files = [target]
    else:
        files = []
        for root, dirs, filenames in os.walk(str(target)):
            dirs[:] = [d for d in dirs if d not in exclude]
            for fname in filenames:
                files.append(Path(root) / fname)

    # Determine which extensions to scan
    allowed_exts: set[str] | None = None
    if languages:
        allowed_exts = set()
        for lang in languages:
            exts = _LANG_EXT_MAP.get(lang.lower(), ())
            allowed_exts.update(exts)

    for fpath in files:
        ext = fpath.suffix.lower()
        if allowed_exts and ext not in allowed_exts:
            continue

        rules = _EXT_TO_RULES.get(ext, [])
        all_rules = rules + _GENERIC_SECRET_PATTERNS

        if not all_rules:
            continue

        try:
            content = fpath.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            continue

        lines = content.split("\n")
        rel_path = str(fpath.relative_to(target)) if target.is_dir() else fpath.name

        for rule in all_rules:
            for i, line in enumerate(lines, start=1):
                if rule["pattern"].search(line):
                    snippet_start = max(0, i - 3)
                    snippet_end = min(len(lines), i + 2)
                    snippet = "\n".join(lines[snippet_start:snippet_end])

                    findings.append(ScanFindingResult(
                        title=rule["title"],
                        severity=rule["severity"],
                        scan_type="sast",
                        description=rule.get("description", ""),
                        cwe_id=rule.get("cwe", ""),
                        file_path=rel_path,
                        line_number=i,
                        code_snippet=snippet,
                        remediation=rule.get("remediation", ""),
                    ))

    slog.info("sast_scan_complete", path=path, findings_count=len(findings))
    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# SECRET DETECTION
# ═══════════════════════════════════════════════════════════════════════════════

_SECRET_PATTERNS: list[dict] = [
    # AWS
    {"pattern": re.compile(r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}"), "title": "AWS Access Key ID", "severity": "critical", "cwe": "CWE-798"},
    {"pattern": re.compile(r'(?:aws_secret_access_key|AWS_SECRET_ACCESS_KEY)\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?'), "title": "AWS Secret Access Key", "severity": "critical", "cwe": "CWE-798"},
    # Azure
    {"pattern": re.compile(r"(?:AccountKey|SharedAccessKey)\s*=\s*[A-Za-z0-9+/=]{40,}"), "title": "Azure Storage/SAS Key", "severity": "critical", "cwe": "CWE-798"},
    {"pattern": re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE), "title": "Azure Client/Tenant ID (potential)", "severity": "low", "cwe": "CWE-200"},
    # GCP
    {"pattern": re.compile(r'"type"\s*:\s*"service_account"'), "title": "GCP Service Account JSON", "severity": "critical", "cwe": "CWE-798"},
    {"pattern": re.compile(r"AIza[0-9A-Za-z_-]{35}"), "title": "Google API Key", "severity": "high", "cwe": "CWE-798"},
    # GitHub / GitLab
    {"pattern": re.compile(r"(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36,}"), "title": "GitHub Token", "severity": "critical", "cwe": "CWE-798"},
    {"pattern": re.compile(r"glpat-[A-Za-z0-9\-_]{20,}"), "title": "GitLab Personal Access Token", "severity": "critical", "cwe": "CWE-798"},
    # Slack
    {"pattern": re.compile(r"xox[bpsar]-[A-Za-z0-9\-]{10,}"), "title": "Slack Token", "severity": "critical", "cwe": "CWE-798"},
    {"pattern": re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"), "title": "Slack Webhook URL", "severity": "high", "cwe": "CWE-798"},
    # Stripe
    {"pattern": re.compile(r"sk_live_[0-9a-zA-Z]{24,}"), "title": "Stripe Live Secret Key", "severity": "critical", "cwe": "CWE-798"},
    {"pattern": re.compile(r"rk_live_[0-9a-zA-Z]{24,}"), "title": "Stripe Restricted Key", "severity": "critical", "cwe": "CWE-798"},
    # OpenAI
    {"pattern": re.compile(r"sk-[A-Za-z0-9]{20,}"), "title": "OpenAI / Generic SK Key", "severity": "critical", "cwe": "CWE-798"},
    # Database connection strings
    {"pattern": re.compile(r"(?:postgres|mysql|mongodb|redis)://[^\s'\"]+:[^\s'\"]+@[^\s'\"]+"), "title": "Database Connection String with Credentials", "severity": "critical", "cwe": "CWE-798"},
    {"pattern": re.compile(r"(?:Data Source|Server)\s*=.*(?:Password|Pwd)\s*=", re.IGNORECASE), "title": "SQL Server Connection String", "severity": "critical", "cwe": "CWE-798"},
    # Private keys
    {"pattern": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"), "title": "Private Key (RSA/EC/SSH)", "severity": "critical", "cwe": "CWE-321"},
    {"pattern": re.compile(r"-----BEGIN PGP PRIVATE KEY BLOCK-----"), "title": "PGP Private Key", "severity": "critical", "cwe": "CWE-321"},
    # JWT
    {"pattern": re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}"), "title": "JWT Token", "severity": "medium", "cwe": "CWE-200"},
    # Generic patterns
    {"pattern": re.compile(r'(?:api[_-]?key|apikey)\s*[=:]\s*["\']?[A-Za-z0-9_\-]{16,}["\']?', re.IGNORECASE), "title": "Generic API Key", "severity": "high", "cwe": "CWE-798"},
    {"pattern": re.compile(r'(?:password|passwd|pwd)\s*[=:]\s*["\'][^"\']{4,}["\']', re.IGNORECASE), "title": "Hardcoded Password", "severity": "high", "cwe": "CWE-798"},
    {"pattern": re.compile(r'(?:auth[_-]?token|access[_-]?token|bearer[_-]?token)\s*[=:]\s*["\']?[A-Za-z0-9_\-\.]{16,}["\']?', re.IGNORECASE), "title": "Hardcoded Auth Token", "severity": "high", "cwe": "CWE-798"},
    {"pattern": re.compile(r'(?:client[_-]?secret)\s*[=:]\s*["\']?[A-Za-z0-9_\-]{16,}["\']?', re.IGNORECASE), "title": "OAuth Client Secret", "severity": "high", "cwe": "CWE-798"},
    # SendGrid / Twilio / Mailgun
    {"pattern": re.compile(r"SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}"), "title": "SendGrid API Key", "severity": "critical", "cwe": "CWE-798"},
    {"pattern": re.compile(r"SK[0-9a-fA-F]{32}"), "title": "Twilio API Key", "severity": "high", "cwe": "CWE-798"},
    {"pattern": re.compile(r"key-[0-9a-zA-Z]{32}"), "title": "Mailgun API Key", "severity": "high", "cwe": "CWE-798"},
    # Heroku / Firebase
    {"pattern": re.compile(r"(?:heroku_api_key|HEROKU_API_KEY)\s*[=:]\s*[0-9a-f-]{36}"), "title": "Heroku API Key", "severity": "high", "cwe": "CWE-798"},
    {"pattern": re.compile(r"AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}"), "title": "Firebase Cloud Messaging Key", "severity": "high", "cwe": "CWE-798"},
    # NPM / PyPI
    {"pattern": re.compile(r"npm_[A-Za-z0-9]{36}"), "title": "npm Access Token", "severity": "critical", "cwe": "CWE-798"},
    {"pattern": re.compile(r"pypi-[A-Za-z0-9_-]{50,}"), "title": "PyPI API Token", "severity": "critical", "cwe": "CWE-798"},
    # SSH
    {"pattern": re.compile(r"ssh-(?:rsa|ed25519|dss)\s+[A-Za-z0-9+/=]{40,}"), "title": "SSH Public Key (check for paired private key)", "severity": "info", "cwe": "CWE-200"},
]

_SECRET_SCAN_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".java", ".go", ".php", ".rb",
    ".yml", ".yaml", ".json", ".xml", ".toml", ".cfg", ".ini", ".conf",
    ".env", ".sh", ".bash", ".zsh", ".ps1", ".bat", ".cmd",
    ".tf", ".tfvars", ".hcl",
    ".properties", ".gradle", ".sql",
    ".md", ".txt", ".rst",
}


async def _run_secret_detection_regex(
    path: str,
    scan_env_files: bool = True,
    scan_git_history: bool = False,
    exclude_dirs: list[str] | None = None,
) -> list[ScanFindingResult]:
    """Detect secrets in files and optionally in git history (regex fallback)."""
    findings: list[ScanFindingResult] = []
    target = Path(path)
    exclude = set(exclude_dirs or [".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"])

    if target.is_file():
        files = [target]
    else:
        files = []
        for root, dirs, filenames in os.walk(str(target)):
            dirs[:] = [d for d in dirs if d not in exclude]
            for fname in filenames:
                fp = Path(root) / fname
                ext = fp.suffix.lower()
                basename = fp.name.lower()
                if ext in _SECRET_SCAN_EXTENSIONS or basename in (".env", ".env.local", ".env.production", ".env.development"):
                    files.append(fp)

    for fpath in files:
        try:
            content = fpath.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            continue

        lines = content.split("\n")
        rel_path = str(fpath.relative_to(target)) if target.is_dir() else fpath.name

        for rule in _SECRET_PATTERNS:
            for i, line in enumerate(lines, start=1):
                if rule["pattern"].search(line):
                    # mask the actual secret in the snippet
                    masked_line = rule["pattern"].sub("[REDACTED]", line)
                    findings.append(ScanFindingResult(
                        title=rule["title"],
                        severity=rule["severity"],
                        scan_type="secrets",
                        description=f"Potential secret detected: {rule['title']}",
                        cwe_id=rule.get("cwe", "CWE-798"),
                        file_path=rel_path,
                        line_number=i,
                        code_snippet=masked_line.strip(),
                        remediation="Remove the secret from source code. Rotate the credential. Use a secrets manager or environment variables.",
                    ))

    # Git history scan (simplified — check last N commits)
    if scan_git_history and target.is_dir():
        git_findings = await _scan_git_history(str(target))
        findings.extend(git_findings)

    slog.info("secret_scan_complete", path=path, findings_count=len(findings))
    return findings


async def _scan_git_history(repo_path: str, max_commits: int = 50) -> list[ScanFindingResult]:
    """Scan recent git history for leaked secrets."""
    findings: list[ScanFindingResult] = []
    try:
        proc = await asyncio.create_subprocess_exec(
            "git", "log", f"--max-count={max_commits}", "--diff-filter=A", "--name-only", "--pretty=format:%H",
            cwd=repo_path,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        if proc.returncode != 0:
            return findings

        # For each commit, check the diff for secret patterns
        commits = stdout.decode(errors="ignore").strip().split("\n\n")
        for block in commits[:max_commits]:
            lines = block.strip().split("\n")
            if not lines:
                continue
            commit_hash = lines[0]

            proc2 = await asyncio.create_subprocess_exec(
                "git", "diff", f"{commit_hash}~1..{commit_hash}", "--",
                cwd=repo_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            diff_out, _ = await proc2.communicate()
            diff_text = diff_out.decode(errors="ignore")

            for rule in _SECRET_PATTERNS:
                if rule["pattern"].search(diff_text):
                    findings.append(ScanFindingResult(
                        title=f"{rule['title']} (in git history)",
                        severity=rule["severity"],
                        scan_type="secrets",
                        description=f"Secret found in git commit {commit_hash[:8]}. Even if removed, it persists in history.",
                        cwe_id=rule.get("cwe", "CWE-798"),
                        file_path=f"git:{commit_hash[:8]}",
                        remediation="Rotate the credential immediately. Use git-filter-repo or BFG to rewrite history.",
                    ))
    except Exception as exc:
        slog.warning("git_history_scan_failed", error=str(exc))

    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# SCA — SOFTWARE COMPOSITION ANALYSIS
# ═══════════════════════════════════════════════════════════════════════════════

_MANIFEST_FILES = {
    "requirements.txt": "python",
    "Pipfile": "python",
    "pyproject.toml": "python",
    "poetry.lock": "python",
    "package.json": "javascript",
    "package-lock.json": "javascript",
    "yarn.lock": "javascript",
    "go.mod": "go",
    "go.sum": "go",
    "pom.xml": "java",
    "build.gradle": "java",
    "Gemfile": "ruby",
    "Gemfile.lock": "ruby",
    "Cargo.toml": "rust",
    "Cargo.lock": "rust",
    "composer.json": "php",
    "composer.lock": "php",
}

_KNOWN_VULNERABLE_PACKAGES: dict[str, list[dict]] = {
    "python": [
        {"name": "pyyaml", "vulnerable_below": "5.4", "cve": "CVE-2020-14343", "severity": "critical", "description": "Arbitrary code execution via yaml.load()"},
        {"name": "requests", "vulnerable_below": "2.31.0", "cve": "CVE-2023-32681", "severity": "medium", "description": "Unintended leak of Proxy-Authorization header"},
        {"name": "urllib3", "vulnerable_below": "2.0.7", "cve": "CVE-2023-45803", "severity": "medium", "description": "Request body not stripped after redirect"},
        {"name": "django", "vulnerable_below": "4.2.8", "cve": "CVE-2023-46695", "severity": "high", "description": "Potential denial of service in UsernameField"},
        {"name": "flask", "vulnerable_below": "2.3.2", "cve": "CVE-2023-30861", "severity": "high", "description": "Cookie caching vulnerability"},
        {"name": "cryptography", "vulnerable_below": "41.0.6", "cve": "CVE-2023-49083", "severity": "high", "description": "NULL pointer dereference in PKCS12 parsing"},
        {"name": "pillow", "vulnerable_below": "10.0.1", "cve": "CVE-2023-44271", "severity": "high", "description": "Denial of service via oversized image"},
        {"name": "jinja2", "vulnerable_below": "3.1.3", "cve": "CVE-2024-22195", "severity": "medium", "description": "XSS via xmlattr filter"},
    ],
    "javascript": [
        {"name": "lodash", "vulnerable_below": "4.17.21", "cve": "CVE-2021-23337", "severity": "critical", "description": "Prototype pollution via template function"},
        {"name": "express", "vulnerable_below": "4.19.2", "cve": "CVE-2024-29041", "severity": "medium", "description": "Open redirect via malformed URL"},
        {"name": "axios", "vulnerable_below": "1.6.0", "cve": "CVE-2023-45857", "severity": "medium", "description": "CSRF via X-XSRF-TOKEN header exposure"},
        {"name": "jsonwebtoken", "vulnerable_below": "9.0.0", "cve": "CVE-2022-23529", "severity": "critical", "description": "Key confusion attack leading to RCE"},
        {"name": "semver", "vulnerable_below": "7.5.2", "cve": "CVE-2022-25883", "severity": "medium", "description": "ReDoS vulnerability"},
        {"name": "minimatch", "vulnerable_below": "3.1.2", "cve": "CVE-2022-3517", "severity": "high", "description": "ReDoS vulnerability"},
    ],
}

# Common license classifications
_LICENSE_MAP: dict[str, str] = {
    "MIT": "permissive",
    "Apache-2.0": "permissive",
    "BSD-2-Clause": "permissive",
    "BSD-3-Clause": "permissive",
    "ISC": "permissive",
    "GPL-2.0": "copyleft",
    "GPL-3.0": "copyleft",
    "AGPL-3.0": "copyleft",
    "LGPL-2.1": "weak-copyleft",
    "LGPL-3.0": "weak-copyleft",
    "MPL-2.0": "weak-copyleft",
    "Unlicense": "public-domain",
    "CC0-1.0": "public-domain",
}


def _parse_requirements_txt(content: str) -> list[dict]:
    """Parse requirements.txt into package list."""
    packages = []
    for line in content.split("\n"):
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        match = re.match(r"^([A-Za-z0-9_.-]+)\s*(?:[=<>!~]+\s*(.+))?", line)
        if match:
            packages.append({"name": match.group(1).lower(), "version": (match.group(2) or "").strip()})
    return packages


def _parse_package_json(content: str) -> list[dict]:
    """Parse package.json into package list."""
    packages = []
    try:
        data = json.loads(content)
        for section in ("dependencies", "devDependencies"):
            deps = data.get(section, {})
            for name, version in deps.items():
                clean_ver = re.sub(r"[^0-9.]", "", version)
                packages.append({"name": name.lower(), "version": clean_ver})
    except json.JSONDecodeError:
        pass
    return packages


def _parse_go_mod(content: str) -> list[dict]:
    """Parse go.mod into package list."""
    packages = []
    in_require = False
    for line in content.split("\n"):
        line = line.strip()
        if line.startswith("require ("):
            in_require = True
            continue
        if line == ")":
            in_require = False
            continue
        if in_require or line.startswith("require "):
            match = re.match(r"(?:require\s+)?(\S+)\s+v?(\S+)", line)
            if match:
                packages.append({"name": match.group(1), "version": match.group(2)})
    return packages


def _parse_pom_xml(content: str) -> list[dict]:
    """Parse pom.xml for dependencies (simple regex-based)."""
    packages = []
    deps = re.findall(
        r"<dependency>\s*<groupId>(.*?)</groupId>\s*<artifactId>(.*?)</artifactId>\s*(?:<version>(.*?)</version>)?",
        content, re.DOTALL,
    )
    for gid, aid, ver in deps:
        packages.append({"name": f"{gid}:{aid}", "version": ver or ""})
    return packages


def _parse_gemfile(content: str) -> list[dict]:
    """Parse Gemfile for gem dependencies."""
    packages = []
    for line in content.split("\n"):
        match = re.match(r"""gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?""", line.strip())
        if match:
            packages.append({"name": match.group(1), "version": (match.group(2) or "").lstrip("~>= ")})
    return packages


def _parse_cargo_toml(content: str) -> list[dict]:
    """Parse Cargo.toml for dependencies."""
    packages = []
    in_deps = False
    for line in content.split("\n"):
        stripped = line.strip()
        if re.match(r"\[.*dependencies.*\]", stripped):
            in_deps = True
            continue
        if stripped.startswith("[") and in_deps:
            in_deps = False
            continue
        if in_deps:
            match = re.match(r'(\S+)\s*=\s*"([^"]*)"', stripped)
            if match:
                packages.append({"name": match.group(1), "version": match.group(2)})
    return packages


_MANIFEST_PARSERS = {
    "requirements.txt": _parse_requirements_txt,
    "package.json": _parse_package_json,
    "go.mod": _parse_go_mod,
    "pom.xml": _parse_pom_xml,
    "Gemfile": _parse_gemfile,
    "Cargo.toml": _parse_cargo_toml,
}


def _version_lt(a: str, b: str) -> bool:
    """Simple version comparison — returns True if a < b."""
    try:
        a_parts = [int(x) for x in re.split(r"[._-]", a) if x.isdigit()]
        b_parts = [int(x) for x in re.split(r"[._-]", b) if x.isdigit()]
        return a_parts < b_parts
    except (ValueError, TypeError):
        return False


async def _run_sca_regex(
    path: str,
    check_vulnerabilities: bool = True,
    check_licenses: bool = True,
    exclude_dirs: list[str] | None = None,
) -> list[ScanFindingResult]:
    """Run Software Composition Analysis on dependency manifests (regex/OSV fallback)."""
    findings: list[ScanFindingResult] = []
    target = Path(path)
    exclude = set(exclude_dirs or [".git", "node_modules", "__pycache__", ".venv", "venv"])

    manifest_files: list[tuple[Path, str]] = []

    if target.is_file():
        fname = target.name
        if fname in _MANIFEST_FILES:
            manifest_files.append((target, fname))
    else:
        for root, dirs, filenames in os.walk(str(target)):
            dirs[:] = [d for d in dirs if d not in exclude]
            for fname in filenames:
                if fname in _MANIFEST_FILES:
                    manifest_files.append((Path(root) / fname, fname))

    for fpath, fname in manifest_files:
        try:
            content = fpath.read_text(encoding="utf-8", errors="ignore")
        except (OSError, PermissionError):
            continue

        rel_path = str(fpath.relative_to(target)) if target.is_dir() else fpath.name
        language = _MANIFEST_FILES.get(fname, "unknown")

        parser = _MANIFEST_PARSERS.get(fname)
        if not parser:
            continue

        packages = parser(content)

        if check_vulnerabilities:
            vuln_db = _KNOWN_VULNERABLE_PACKAGES.get(language, [])
            for pkg in packages:
                for vuln in vuln_db:
                    if pkg["name"] == vuln["name"] and pkg["version"] and _version_lt(pkg["version"], vuln["vulnerable_below"]):
                        findings.append(ScanFindingResult(
                            title=f"Vulnerable dependency: {pkg['name']}@{pkg['version']}",
                            severity=vuln["severity"],
                            scan_type="sca",
                            description=f"{vuln['cve']}: {vuln['description']}. Fixed in {vuln['vulnerable_below']}+.",
                            cwe_id="CWE-1395",
                            file_path=rel_path,
                            code_snippet=f"{pkg['name']}=={pkg['version']}",
                            remediation=f"Upgrade {pkg['name']} to version {vuln['vulnerable_below']} or later.",
                        ))

        # Also check via OSV API if httpx is available
        if check_vulnerabilities:
            osv_findings = await _check_osv(packages, language, rel_path)
            findings.extend(osv_findings)

    slog.info("sca_scan_complete", path=path, findings_count=len(findings))
    return findings


async def _check_osv(packages: list[dict], ecosystem: str, manifest_path: str) -> list[ScanFindingResult]:
    """Check packages against the OSV.dev API for known vulnerabilities."""
    findings: list[ScanFindingResult] = []
    eco_map = {"python": "PyPI", "javascript": "npm", "go": "Go", "rust": "crates.io", "ruby": "RubyGems", "java": "Maven"}
    osv_ecosystem = eco_map.get(ecosystem)
    if not osv_ecosystem:
        return findings

    queries = []
    pkg_names = []
    for pkg in packages:
        if pkg["version"]:
            queries.append({"package": {"name": pkg["name"], "ecosystem": osv_ecosystem}, "version": pkg["version"]})
            pkg_names.append(pkg["name"])

    if not queries:
        return findings

    try:
        async with httpx.AsyncClient(timeout=15.0) as client:
            resp = await client.post("https://api.osv.dev/v1/querybatch", json={"queries": queries})
            if resp.status_code == 200:
                data = resp.json()
                for i, result in enumerate(data.get("results", [])):
                    vulns = result.get("vulns", [])
                    for vuln in vulns:
                        vuln_id = vuln.get("id", "UNKNOWN")
                        summary = vuln.get("summary", "Known vulnerability")
                        severity = "high"  # OSV does not always provide severity
                        findings.append(ScanFindingResult(
                            title=f"OSV: {pkg_names[i]} — {vuln_id}",
                            severity=severity,
                            scan_type="sca",
                            description=summary,
                            cwe_id="CWE-1395",
                            file_path=manifest_path,
                            code_snippet=f"{pkg_names[i]} (via OSV)",
                            remediation=f"Check https://osv.dev/vulnerability/{vuln_id} for remediation.",
                        ))
    except Exception as exc:
        slog.warning("osv_check_failed", error=str(exc))

    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# DAST — DYNAMIC APPLICATION SECURITY TESTING
# ═══════════════════════════════════════════════════════════════════════════════


async def _run_dast_internal(
    target_url: str,
    checks: list[str] | None = None,
    auth: dict[str, str] | None = None,
    timeout: float = 15.0,
    max_pages: int = 50,
) -> list[ScanFindingResult]:
    """Run DAST scan against a live application (in-process httpx-based)."""
    findings: list[ScanFindingResult] = []
    all_checks = checks or ["headers", "ssl", "cors", "xss_reflected", "sqli_error", "open_redirect", "info_disclosure"]

    headers: dict[str, str] = {"User-Agent": "DevSecOps-Scanner/1.0"}
    if auth:
        if "token" in auth:
            headers["Authorization"] = f"Bearer {auth['token']}"
        elif "cookie" in auth:
            headers["Cookie"] = auth["cookie"]

    async with httpx.AsyncClient(timeout=timeout, headers=headers, follow_redirects=False, verify=False) as client:
        # Crawl for pages
        pages = await _crawl(client, target_url, max_pages)

        for page_url in pages:
            if "headers" in all_checks:
                findings.extend(await _check_security_headers(client, page_url))
            if "cors" in all_checks:
                findings.extend(await _check_cors(client, page_url))
            if "xss_reflected" in all_checks:
                findings.extend(await _check_reflected_xss(client, page_url))
            if "sqli_error" in all_checks:
                findings.extend(await _check_error_sqli(client, page_url))
            if "open_redirect" in all_checks:
                findings.extend(await _check_open_redirect(client, page_url))
            if "info_disclosure" in all_checks:
                findings.extend(await _check_info_disclosure(client, page_url))

    slog.info("dast_scan_complete", target=target_url, pages=len(pages), findings_count=len(findings))
    return findings


async def _crawl(client: httpx.AsyncClient, start_url: str, max_pages: int) -> list[str]:
    """Simple crawler to discover pages."""
    from urllib.parse import urljoin, urlparse
    visited: set[str] = set()
    to_visit = [start_url]
    pages: list[str] = []

    base_domain = urlparse(start_url).netloc

    while to_visit and len(pages) < max_pages:
        url = to_visit.pop(0)
        if url in visited:
            continue
        visited.add(url)

        try:
            resp = await client.get(url)
            pages.append(url)

            if "text/html" in resp.headers.get("content-type", ""):
                links = re.findall(r'href=["\']([^"\']+)["\']', resp.text)
                for link in links:
                    full_url = urljoin(url, link)
                    parsed = urlparse(full_url)
                    if parsed.netloc == base_domain and full_url not in visited:
                        to_visit.append(full_url.split("#")[0])
        except Exception:
            continue

    return pages


async def _check_security_headers(client: httpx.AsyncClient, url: str) -> list[ScanFindingResult]:
    """Check for missing security headers."""
    findings: list[ScanFindingResult] = []
    try:
        resp = await client.get(url)
        headers_lower = {k.lower(): v for k, v in resp.headers.items()}

        required = {
            "x-content-type-options": ("Missing X-Content-Type-Options header", "medium", "CWE-16", "Add: X-Content-Type-Options: nosniff"),
            "x-frame-options": ("Missing X-Frame-Options header", "medium", "CWE-1021", "Add: X-Frame-Options: DENY or SAMEORIGIN"),
            "strict-transport-security": ("Missing HSTS header", "medium", "CWE-319", "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains"),
            "content-security-policy": ("Missing Content-Security-Policy header", "medium", "CWE-16", "Define a strict CSP policy"),
            "x-xss-protection": ("Missing X-XSS-Protection header", "low", "CWE-79", "Add: X-XSS-Protection: 1; mode=block"),
        }

        for header, (title, sev, cwe, remed) in required.items():
            if header not in headers_lower:
                findings.append(ScanFindingResult(
                    title=title, severity=sev, scan_type="dast",
                    description=f"The header '{header}' is missing on {url}.",
                    cwe_id=cwe, file_path=url, remediation=remed,
                ))

        if "server" in headers_lower:
            findings.append(ScanFindingResult(
                title="Server header information disclosure",
                severity="low", scan_type="dast",
                description=f"Server header reveals: {headers_lower['server']}",
                cwe_id="CWE-200", file_path=url,
                remediation="Remove or obfuscate the Server header.",
            ))
    except Exception:
        pass
    return findings


async def _check_cors(client: httpx.AsyncClient, url: str) -> list[ScanFindingResult]:
    """Check for permissive CORS configuration."""
    findings: list[ScanFindingResult] = []
    try:
        resp = await client.get(url, headers={"Origin": "https://evil.attacker.com"})
        acao = resp.headers.get("access-control-allow-origin", "")
        if acao == "*" or acao == "https://evil.attacker.com":
            findings.append(ScanFindingResult(
                title="Permissive CORS configuration",
                severity="high", scan_type="dast",
                description=f"CORS allows arbitrary origins: {acao}",
                cwe_id="CWE-942", file_path=url,
                remediation="Restrict Access-Control-Allow-Origin to trusted domains.",
            ))
    except Exception:
        pass
    return findings


async def _check_reflected_xss(client: httpx.AsyncClient, url: str) -> list[ScanFindingResult]:
    """Check for reflected XSS with simple payloads."""
    findings: list[ScanFindingResult] = []
    canary = f"xss{uuid.uuid4().hex[:8]}"
    payload = f"<script>{canary}</script>"
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    if not params:
        # Try appending a test parameter
        params = {"q": [payload], "search": [payload], "id": [payload]}

    for param_name in list(params.keys())[:5]:
        test_params = {**{k: v[0] if isinstance(v, list) else v for k, v in params.items()}, param_name: payload}
        test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
        try:
            resp = await client.get(test_url)
            if canary in resp.text:
                findings.append(ScanFindingResult(
                    title=f"Reflected XSS via parameter '{param_name}'",
                    severity="high", scan_type="dast",
                    description=f"Injected script tag reflected in response at {test_url}.",
                    cwe_id="CWE-79", file_path=url,
                    remediation="Sanitize and encode all user input before rendering in HTML.",
                ))
        except Exception:
            pass
    return findings


async def _check_error_sqli(client: httpx.AsyncClient, url: str) -> list[ScanFindingResult]:
    """Check for error-based SQL injection indicators."""
    findings: list[ScanFindingResult] = []
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

    parsed = urlparse(url)
    params = parse_qs(parsed.query)

    sqli_errors = [
        "you have an error in your sql syntax",
        "unclosed quotation mark",
        "syntax error at or near",
        "ORA-01756",
        "Microsoft OLE DB Provider",
        "SQLITE_ERROR",
        "pg_query",
        "mysql_fetch",
    ]

    for param_name in list(params.keys())[:5]:
        test_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
        test_params[param_name] = "' OR '1'='1"
        test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
        try:
            resp = await client.get(test_url)
            body_lower = resp.text.lower()
            for err in sqli_errors:
                if err.lower() in body_lower:
                    findings.append(ScanFindingResult(
                        title=f"SQL Injection (error-based) via '{param_name}'",
                        severity="critical", scan_type="dast",
                        description=f"SQL error message detected when injecting into parameter '{param_name}'.",
                        cwe_id="CWE-89", file_path=url,
                        remediation="Use parameterized queries. Never concatenate user input into SQL.",
                    ))
                    break
        except Exception:
            pass
    return findings


async def _check_open_redirect(client: httpx.AsyncClient, url: str) -> list[ScanFindingResult]:
    """Check for open redirect vulnerabilities."""
    findings: list[ScanFindingResult] = []
    from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

    parsed = urlparse(url)
    params = parse_qs(parsed.query)
    redirect_params = [p for p in params if p.lower() in ("url", "redirect", "next", "return", "returnto", "goto", "dest", "destination", "redir", "redirect_uri")]

    for param_name in redirect_params:
        test_params = {k: v[0] if isinstance(v, list) else v for k, v in params.items()}
        test_params[param_name] = "https://evil.attacker.com"
        test_url = urlunparse(parsed._replace(query=urlencode(test_params)))
        try:
            resp = await client.get(test_url)
            location = resp.headers.get("location", "")
            if "evil.attacker.com" in location:
                findings.append(ScanFindingResult(
                    title=f"Open Redirect via '{param_name}'",
                    severity="medium", scan_type="dast",
                    description=f"Application redirects to attacker-controlled URL via '{param_name}'.",
                    cwe_id="CWE-601", file_path=url,
                    remediation="Validate redirect URLs against a whitelist of allowed domains.",
                ))
        except Exception:
            pass
    return findings


async def _check_info_disclosure(client: httpx.AsyncClient, url: str) -> list[ScanFindingResult]:
    """Check for common information disclosure paths."""
    findings: list[ScanFindingResult] = []
    from urllib.parse import urljoin

    sensitive_paths = [
        ("/.env", "Environment file exposed"),
        ("/.git/config", "Git repository exposed"),
        ("/phpinfo.php", "PHP info page exposed"),
        ("/server-status", "Apache server-status exposed"),
        ("/debug", "Debug endpoint exposed"),
        ("/.DS_Store", "macOS metadata file exposed"),
        ("/wp-config.php.bak", "WordPress config backup exposed"),
        ("/robots.txt", "Robots.txt (informational)"),
        ("/.well-known/security.txt", "Security.txt (informational)"),
    ]

    for path, title in sensitive_paths:
        try:
            check_url = urljoin(url, path)
            resp = await client.get(check_url)
            if resp.status_code == 200 and len(resp.content) > 10:
                sev = "info" if "informational" in title else "high"
                findings.append(ScanFindingResult(
                    title=title,
                    severity=sev, scan_type="dast",
                    description=f"Sensitive file/endpoint accessible at {check_url} (HTTP {resp.status_code}).",
                    cwe_id="CWE-200", file_path=check_url,
                    remediation="Restrict access to sensitive files. Configure web server to deny access.",
                ))
        except Exception:
            pass
    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# CONTAINER SECURITY
# ═══════════════════════════════════════════════════════════════════════════════


async def _run_container_scan_regex(
    path: str,
    exclude_dirs: list[str] | None = None,
) -> list[ScanFindingResult]:
    """Analyze Dockerfiles and docker-compose files for security issues (regex fallback)."""
    findings: list[ScanFindingResult] = []
    target = Path(path)
    exclude = set(exclude_dirs or [".git", "node_modules", "__pycache__"])

    docker_files: list[Path] = []
    compose_files: list[Path] = []

    if target.is_file():
        name = target.name.lower()
        if "dockerfile" in name:
            docker_files.append(target)
        elif "docker-compose" in name or "compose.y" in name:
            compose_files.append(target)
    else:
        for root, dirs, filenames in os.walk(str(target)):
            dirs[:] = [d for d in dirs if d not in exclude]
            for fname in filenames:
                fl = fname.lower()
                fp = Path(root) / fname
                if "dockerfile" in fl:
                    docker_files.append(fp)
                elif fl in ("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"):
                    compose_files.append(fp)

    for fpath in docker_files:
        findings.extend(_analyze_dockerfile(fpath, target))

    for fpath in compose_files:
        findings.extend(_analyze_docker_compose(fpath, target))

    slog.info("container_scan_complete", path=path, findings_count=len(findings))
    return findings


def _analyze_dockerfile(fpath: Path, base: Path) -> list[ScanFindingResult]:
    """Analyze a Dockerfile for security issues."""
    findings: list[ScanFindingResult] = []
    try:
        content = fpath.read_text(encoding="utf-8", errors="ignore")
    except (OSError, PermissionError):
        return findings

    rel = str(fpath.relative_to(base)) if base.is_dir() else fpath.name
    lines = content.split("\n")
    has_user = False

    for i, line in enumerate(lines, start=1):
        stripped = line.strip().upper()

        # Check for running as root
        if stripped.startswith("USER "):
            has_user = True
            user_val = line.strip().split(None, 1)[1].strip() if len(line.strip().split(None, 1)) > 1 else ""
            if user_val.lower() in ("root", "0"):
                findings.append(ScanFindingResult(
                    title="Container runs as root",
                    severity="high", scan_type="container",
                    description="Dockerfile explicitly sets USER to root.",
                    cwe_id="CWE-250", file_path=rel, line_number=i,
                    code_snippet=line.strip(),
                    remediation="Create and use a non-root user: RUN adduser -D appuser && USER appuser",
                ))

        # Check for latest tag
        if stripped.startswith("FROM ") and ":latest" in line.lower():
            findings.append(ScanFindingResult(
                title="Using 'latest' tag in FROM",
                severity="medium", scan_type="container",
                description="Using :latest tag makes builds non-reproducible.",
                cwe_id="CWE-1104", file_path=rel, line_number=i,
                code_snippet=line.strip(),
                remediation="Pin a specific image version, e.g., python:3.12-slim.",
            ))

        # No tag at all on FROM
        if stripped.startswith("FROM ") and ":" not in line and "AS" not in stripped:
            findings.append(ScanFindingResult(
                title="No tag specified in FROM",
                severity="medium", scan_type="container",
                description="FROM without a tag defaults to :latest.",
                cwe_id="CWE-1104", file_path=rel, line_number=i,
                code_snippet=line.strip(),
                remediation="Pin a specific image version.",
            ))

        # ADD vs COPY
        if stripped.startswith("ADD ") and not any(x in line for x in ["http://", "https://", ".tar", ".gz"]):
            findings.append(ScanFindingResult(
                title="Use COPY instead of ADD",
                severity="low", scan_type="container",
                description="ADD has extra features (URL download, tar extraction) that can be unexpected.",
                cwe_id="CWE-1104", file_path=rel, line_number=i,
                code_snippet=line.strip(),
                remediation="Use COPY unless you specifically need ADD features.",
            ))

        # Expose sensitive ports
        if stripped.startswith("EXPOSE "):
            ports = re.findall(r"\d+", line)
            sensitive = {"22", "23", "3389", "5432", "3306", "27017", "6379", "11211"}
            for port in ports:
                if port in sensitive:
                    findings.append(ScanFindingResult(
                        title=f"Exposing sensitive port {port}",
                        severity="medium", scan_type="container",
                        description=f"Port {port} is commonly associated with sensitive services.",
                        cwe_id="CWE-200", file_path=rel, line_number=i,
                        code_snippet=line.strip(),
                        remediation="Avoid exposing database/admin ports directly. Use internal networks.",
                    ))

        # curl | bash pattern
        if re.search(r"curl\s.*\|\s*(?:bash|sh)", line, re.IGNORECASE):
            findings.append(ScanFindingResult(
                title="Curl pipe to shell",
                severity="high", scan_type="container",
                description="Piping curl output to shell is dangerous — content could be tampered.",
                cwe_id="CWE-494", file_path=rel, line_number=i,
                code_snippet=line.strip(),
                remediation="Download, verify checksum, then execute separately.",
            ))

    if not has_user:
        findings.append(ScanFindingResult(
            title="No USER instruction — container runs as root",
            severity="high", scan_type="container",
            description="Dockerfile does not set a non-root USER. The container will run as root by default.",
            cwe_id="CWE-250", file_path=rel,
            remediation="Add USER instruction with a non-root user.",
        ))

    return findings


def _analyze_docker_compose(fpath: Path, base: Path) -> list[ScanFindingResult]:
    """Analyze docker-compose.yml for security issues."""
    findings: list[ScanFindingResult] = []
    try:
        content = fpath.read_text(encoding="utf-8", errors="ignore")
    except (OSError, PermissionError):
        return findings

    rel = str(fpath.relative_to(base)) if base.is_dir() else fpath.name

    if "privileged: true" in content:
        findings.append(ScanFindingResult(
            title="Privileged container in docker-compose",
            severity="critical", scan_type="container",
            description="privileged: true gives the container full host access.",
            cwe_id="CWE-250", file_path=rel,
            remediation="Remove privileged: true. Use specific capabilities instead.",
        ))

    if "network_mode: host" in content or 'network_mode: "host"' in content:
        findings.append(ScanFindingResult(
            title="Host network mode in docker-compose",
            severity="high", scan_type="container",
            description="Host network mode exposes all host network interfaces to the container.",
            cwe_id="CWE-668", file_path=rel,
            remediation="Use bridge networking with explicit port mappings.",
        ))

    if "pid: host" in content or 'pid: "host"' in content:
        findings.append(ScanFindingResult(
            title="Host PID namespace in docker-compose",
            severity="high", scan_type="container",
            description="Host PID namespace lets the container see and signal host processes.",
            cwe_id="CWE-668", file_path=rel,
            remediation="Remove pid: host unless absolutely required.",
        ))

    # Sensitive volume mounts
    sensitive_mounts = ["/var/run/docker.sock", "/etc/shadow", "/etc/passwd", "/root"]
    for mount in sensitive_mounts:
        if mount in content:
            findings.append(ScanFindingResult(
                title=f"Sensitive volume mount: {mount}",
                severity="high", scan_type="container",
                description=f"Mounting {mount} gives the container access to sensitive host resources.",
                cwe_id="CWE-668", file_path=rel,
                remediation=f"Avoid mounting {mount} unless absolutely necessary.",
            ))

    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# IaC — INFRASTRUCTURE AS CODE SECURITY
# ═══════════════════════════════════════════════════════════════════════════════


async def _run_iac_scan_regex(
    path: str,
    exclude_dirs: list[str] | None = None,
) -> list[ScanFindingResult]:
    """Scan Infrastructure as Code files for security misconfigurations (regex fallback)."""
    findings: list[ScanFindingResult] = []
    target = Path(path)
    exclude = set(exclude_dirs or [".git", "node_modules", "__pycache__", ".terraform"])

    tf_files: list[Path] = []
    k8s_files: list[Path] = []
    cfn_files: list[Path] = []
    ansible_files: list[Path] = []

    if target.is_file():
        ext = target.suffix.lower()
        name = target.name.lower()
        if ext in (".tf", ".tfvars"):
            tf_files.append(target)
        elif ext in (".yml", ".yaml"):
            # Heuristic: check content for k8s vs ansible vs cfn
            try:
                content = target.read_text(encoding="utf-8", errors="ignore")
                if "apiVersion:" in content and "kind:" in content:
                    k8s_files.append(target)
                elif "AWSTemplateFormatVersion" in content:
                    cfn_files.append(target)
                elif "hosts:" in content or "tasks:" in content:
                    ansible_files.append(target)
            except Exception:
                pass
    else:
        for root, dirs, filenames in os.walk(str(target)):
            dirs[:] = [d for d in dirs if d not in exclude]
            for fname in filenames:
                fp = Path(root) / fname
                ext = fp.suffix.lower()
                if ext in (".tf", ".tfvars"):
                    tf_files.append(fp)
                elif ext in (".yml", ".yaml"):
                    try:
                        sample = fp.read_text(encoding="utf-8", errors="ignore")[:2000]
                        if "apiVersion:" in sample and "kind:" in sample:
                            k8s_files.append(fp)
                        elif "AWSTemplateFormatVersion" in sample:
                            cfn_files.append(fp)
                        elif ("hosts:" in sample or "tasks:" in sample) and "ansible" in str(root).lower():
                            ansible_files.append(fp)
                    except Exception:
                        pass

    for fp in tf_files:
        findings.extend(_scan_terraform(fp, target))
    for fp in k8s_files:
        findings.extend(_scan_kubernetes(fp, target))
    for fp in cfn_files:
        findings.extend(_scan_cloudformation(fp, target))
    for fp in ansible_files:
        findings.extend(_scan_ansible(fp, target))

    slog.info("iac_scan_complete", path=path, findings_count=len(findings))
    return findings


def _scan_terraform(fpath: Path, base: Path) -> list[ScanFindingResult]:
    """Scan Terraform files for security issues."""
    findings: list[ScanFindingResult] = []
    try:
        content = fpath.read_text(encoding="utf-8", errors="ignore")
    except (OSError, PermissionError):
        return findings

    rel = str(fpath.relative_to(base)) if base.is_dir() else fpath.name
    lines = content.split("\n")

    checks = [
        (re.compile(r'cidr_blocks\s*=\s*\[\s*"0\.0\.0\.0/0"\s*\]'), "Security group open to 0.0.0.0/0", "critical", "CWE-284",
         "Restrict CIDR blocks to specific IP ranges."),
        (re.compile(r"acl\s*=\s*\"public-read\""), "S3 bucket with public-read ACL", "critical", "CWE-284",
         "Set acl = 'private' and use bucket policies for access control."),
        (re.compile(r"acl\s*=\s*\"public-read-write\""), "S3 bucket with public-read-write ACL", "critical", "CWE-284",
         "Never use public-read-write. Set acl = 'private'."),
        (re.compile(r"encrypted\s*=\s*false"), "Encryption disabled", "high", "CWE-311",
         "Enable encryption: encrypted = true."),
        (re.compile(r"effect\s*=\s*\"Allow\".*\"Action\"\s*:\s*\"\*\"", re.DOTALL), "IAM policy with Action: *", "critical", "CWE-250",
         "Follow least-privilege principle. Specify exact actions needed."),
        (re.compile(r"protocol\s*=\s*\"-1\""), "Security group allows all protocols", "high", "CWE-284",
         "Restrict to specific protocols (tcp, udp) and ports."),
        (re.compile(r'(?:password|secret)\s*=\s*"[^"]{4,}"', re.IGNORECASE), "Hardcoded secret in Terraform", "critical", "CWE-798",
         "Use variables with sensitive = true and a secrets manager."),
    ]

    for i, line in enumerate(lines, start=1):
        for pattern, title, sev, cwe, remed in checks:
            if pattern.search(line):
                findings.append(ScanFindingResult(
                    title=title, severity=sev, scan_type="iac",
                    cwe_id=cwe, file_path=rel, line_number=i,
                    code_snippet=line.strip(), remediation=remed,
                ))

    return findings


def _scan_kubernetes(fpath: Path, base: Path) -> list[ScanFindingResult]:
    """Scan Kubernetes YAML for security issues."""
    findings: list[ScanFindingResult] = []
    try:
        content = fpath.read_text(encoding="utf-8", errors="ignore")
    except (OSError, PermissionError):
        return findings

    rel = str(fpath.relative_to(base)) if base.is_dir() else fpath.name

    checks = [
        ("privileged: true", "Privileged container in Kubernetes", "critical", "CWE-250",
         "Set privileged: false in securityContext."),
        ("hostPID: true", "Host PID namespace enabled", "high", "CWE-668",
         "Set hostPID: false."),
        ("hostNetwork: true", "Host network enabled", "high", "CWE-668",
         "Set hostNetwork: false. Use ClusterIP services."),
        ("readOnlyRootFilesystem: false", "Writable root filesystem", "medium", "CWE-732",
         "Set readOnlyRootFilesystem: true in securityContext."),
        ("allowPrivilegeEscalation: true", "Privilege escalation allowed", "high", "CWE-250",
         "Set allowPrivilegeEscalation: false."),
        ("runAsUser: 0", "Running as root user", "high", "CWE-250",
         "Set runAsUser to a non-zero UID."),
    ]

    for check_str, title, sev, cwe, remed in checks:
        if check_str in content:
            # Find line number
            for i, line in enumerate(content.split("\n"), start=1):
                if check_str in line:
                    findings.append(ScanFindingResult(
                        title=title, severity=sev, scan_type="iac",
                        cwe_id=cwe, file_path=rel, line_number=i,
                        code_snippet=line.strip(), remediation=remed,
                    ))
                    break

    # Check for missing resource limits
    if "resources:" not in content and ("kind: Deployment" in content or "kind: Pod" in content):
        findings.append(ScanFindingResult(
            title="No resource limits defined",
            severity="medium", scan_type="iac",
            description="Missing resource limits can lead to denial of service.",
            cwe_id="CWE-770", file_path=rel,
            remediation="Add resources.limits and resources.requests for CPU and memory.",
        ))

    # Check for missing securityContext
    if "securityContext:" not in content and ("kind: Deployment" in content or "kind: Pod" in content):
        findings.append(ScanFindingResult(
            title="No securityContext defined",
            severity="medium", scan_type="iac",
            description="Missing securityContext means default (often permissive) settings.",
            cwe_id="CWE-250", file_path=rel,
            remediation="Add securityContext with runAsNonRoot: true, readOnlyRootFilesystem: true.",
        ))

    return findings


def _scan_cloudformation(fpath: Path, base: Path) -> list[ScanFindingResult]:
    """Scan CloudFormation templates for security issues."""
    findings: list[ScanFindingResult] = []
    try:
        content = fpath.read_text(encoding="utf-8", errors="ignore")
    except (OSError, PermissionError):
        return findings

    rel = str(fpath.relative_to(base)) if base.is_dir() else fpath.name

    checks = [
        (re.compile(r"CidrIp:\s*0\.0\.0\.0/0"), "Security group open to 0.0.0.0/0", "critical", "CWE-284"),
        (re.compile(r"PublicAccessBlockConfiguration.*false", re.DOTALL), "S3 public access block disabled", "critical", "CWE-284"),
        (re.compile(r"Encrypted:\s*false", re.IGNORECASE), "Encryption disabled", "high", "CWE-311"),
        (re.compile(r'"Effect"\s*:\s*"Allow".*"Action"\s*:\s*"\*"', re.DOTALL), "IAM policy with Action: *", "critical", "CWE-250"),
    ]

    for i, line in enumerate(content.split("\n"), start=1):
        for pattern, title, sev, cwe in checks:
            if pattern.search(line):
                findings.append(ScanFindingResult(
                    title=title, severity=sev, scan_type="iac",
                    cwe_id=cwe, file_path=rel, line_number=i,
                    code_snippet=line.strip(),
                    remediation="Follow AWS security best practices for this resource.",
                ))

    return findings


def _scan_ansible(fpath: Path, base: Path) -> list[ScanFindingResult]:
    """Scan Ansible playbooks for security issues."""
    findings: list[ScanFindingResult] = []
    try:
        content = fpath.read_text(encoding="utf-8", errors="ignore")
    except (OSError, PermissionError):
        return findings

    rel = str(fpath.relative_to(base)) if base.is_dir() else fpath.name
    lines = content.split("\n")

    checks = [
        (re.compile(r'password\s*:\s*["\']?[^\s{][^"\'}\s]{3,}', re.IGNORECASE), "Hardcoded password in Ansible", "critical", "CWE-798",
         "Use ansible-vault for secrets or reference external secrets manager."),
        (re.compile(r"become:\s*(?:yes|true)", re.IGNORECASE), "Unrestricted become (privilege escalation)", "medium", "CWE-250",
         "Limit become to specific tasks. Use become_user with a non-root account when possible."),
        (re.compile(r"shell:|command:|raw:"), "Shell/command module usage", "low", "CWE-78",
         "Prefer dedicated Ansible modules over shell/command for idempotency and safety."),
    ]

    for i, line in enumerate(lines, start=1):
        for pattern, title, sev, cwe, remed in checks:
            if pattern.search(line):
                findings.append(ScanFindingResult(
                    title=title, severity=sev, scan_type="iac",
                    cwe_id=cwe, file_path=rel, line_number=i,
                    code_snippet=line.strip(), remediation=remed,
                ))

    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# FULL SCAN ORCHESTRATOR
# ═══════════════════════════════════════════════════════════════════════════════


async def run_full_scan(
    path: str,
    scan_types: list[str] | None = None,
    dast_target: str | None = None,
    dast_auth: dict[str, str] | None = None,
    languages: list[str] | None = None,
    exclude_dirs: list[str] | None = None,
) -> dict[str, list[dict]]:
    """Run all scan types and aggregate results (uses real binaries when available)."""
    types = scan_types or ["sast", "sca", "secrets", "container", "iac"]
    results: dict[str, list[dict]] = {}

    tasks = []
    task_names = []

    if "sast" in types:
        tasks.append(run_sast(path, language=languages[0] if languages else None))
        task_names.append("sast")
    if "sca" in types:
        tasks.append(run_sca(path))
        task_names.append("sca")
    if "secrets" in types:
        tasks.append(run_secret_detection(path))
        task_names.append("secrets")
    if "container" in types:
        tasks.append(run_container_scan(path))
        task_names.append("container")
    if "iac" in types:
        tasks.append(run_iac_scan(path))
        task_names.append("iac")
    if "dast" in types and dast_target:
        tasks.append(run_dast(dast_target, options={"auth": dast_auth} if dast_auth else None))
        task_names.append("dast")

    completed = await asyncio.gather(*tasks, return_exceptions=True)
    for name, result in zip(task_names, completed):
        if isinstance(result, Exception):
            slog.error("scan_failed", scan_type=name, error=str(result))
            results[name] = []
        else:
            results[name] = result

    return results


# ═══════════════════════════════════════════════════════════════════════════════
# PUBLIC API — binary-first wrappers with regex fallbacks
# ═══════════════════════════════════════════════════════════════════════════════
#
# Each public ``run_*`` function:
#   1. Tries the real binary engine (Semgrep / Bandit / Safety / Gitleaks /
#      Trivy / Checkov) via ``apps.api.devsecops.scanner_engines``.
#   2. Falls back to the in-process regex scanner above when the binary is
#      missing or returns no parsable output.
#   3. Always returns ``list[dict]`` aligned with ``_persist_run`` in
#      ``apps/api/routes/devsecops.py``.
# ═══════════════════════════════════════════════════════════════════════════════


async def run_sast(
    path: str,
    language: str | None = None,
    options: dict | None = None,
    languages: list[str] | None = None,
    exclude_dirs: list[str] | None = None,
) -> list[dict]:
    """SAST: Semgrep + Bandit (Python) → regex fallback."""
    options = options or {}
    langs = languages or ([language] if language else None) or options.get("languages")

    findings: list[dict] = []
    used_real = False

    semgrep_results = await _engines.semgrep_scan(path)
    if semgrep_results is not None:
        findings.extend(semgrep_results)
        used_real = True

    # Bandit complements Semgrep on Python (or stands alone if Semgrep missing)
    is_python = (langs is None) or any(str(l).lower() in ("python", "py") for l in (langs or []))
    if is_python:
        bandit_results = await _engines.bandit_scan(path)
        if bandit_results is not None:
            findings.extend(bandit_results)
            used_real = True

    if not used_real:
        slog.info("scan_engine_used", scan="sast", engine="regex_fallback")
        regex_findings = await _run_sast_regex(path, languages=langs, exclude_dirs=exclude_dirs)
        findings = _normalize_findings(regex_findings)

    return _normalize_findings(findings)


async def run_sca(
    path: str,
    options: dict | None = None,
    check_vulnerabilities: bool = True,
    check_licenses: bool = True,
    exclude_dirs: list[str] | None = None,
) -> list[dict]:
    """SCA: Safety (Python) + always run the OSV-backed regex engine for cross-ecosystem coverage."""
    options = options or {}

    findings: list[dict] = []
    used_real = False

    safety_results = await _engines.safety_scan(path)
    if safety_results is not None:
        findings.extend(safety_results)
        used_real = True

    # Keep the OSV-powered regex pipeline — covers npm/Go/Maven/Gemfile/Cargo
    regex_findings = await _run_sca_regex(
        path,
        check_vulnerabilities=check_vulnerabilities,
        check_licenses=check_licenses,
        exclude_dirs=exclude_dirs,
    )
    findings.extend(_normalize_findings(regex_findings))

    if not used_real:
        slog.info("scan_engine_used", scan="sca", engine="regex_fallback+osv")

    return _normalize_findings(findings)


async def run_secret_detection(
    path: str,
    options: dict | None = None,
    scan_env_files: bool = True,
    scan_git_history: bool = False,
    exclude_dirs: list[str] | None = None,
) -> list[dict]:
    """Secrets: Gitleaks → regex fallback. Git-history regex pass kept as bonus."""
    options = options or {}
    scan_git_history = options.get("scan_git_history", scan_git_history)

    findings: list[dict] = []
    used_real = False

    gitleaks_results = await _engines.gitleaks_scan(path)
    if gitleaks_results is not None:
        findings.extend(gitleaks_results)
        used_real = True

    if not used_real:
        slog.info("scan_engine_used", scan="secrets", engine="regex_fallback")
        regex_findings = await _run_secret_detection_regex(
            path,
            scan_env_files=scan_env_files,
            scan_git_history=scan_git_history,
            exclude_dirs=exclude_dirs,
        )
        findings.extend(_normalize_findings(regex_findings))
    elif scan_git_history:
        # Bonus: still run our git-history regex sweep
        from pathlib import Path as _P
        if _P(path).is_dir():
            git_findings = await _scan_git_history(path)
            findings.extend(_normalize_findings(git_findings))

    return _normalize_findings(findings)


async def run_dast(
    target: str,
    options: dict | None = None,
    checks: list[str] | None = None,
    auth: dict[str, str] | None = None,
    timeout: float = 15.0,
    max_pages: int = 50,
) -> list[dict]:
    """DAST: in-process httpx-based scan. (Nuclei integration is a future enhancement.)"""
    options = options or {}
    auth = auth or options.get("auth")
    checks = checks or options.get("checks")
    timeout = float(options.get("timeout", timeout))
    max_pages = int(options.get("max_pages", max_pages))

    slog.info("scan_engine_used", scan="dast", engine="builtin_httpx")
    results = await _run_dast_internal(target, checks=checks, auth=auth, timeout=timeout, max_pages=max_pages)
    return _normalize_findings(results)


async def run_container_scan(
    target: str,
    options: dict | None = None,
    exclude_dirs: list[str] | None = None,
) -> list[dict]:
    """Container: Trivy (fs or image) → regex Dockerfile/compose fallback."""
    options = options or {}

    findings: list[dict] = []
    used_real = False

    trivy_results = await _engines.trivy_scan(target)
    if trivy_results is not None:
        findings.extend(trivy_results)
        used_real = True

    # Always also lint the Dockerfile/compose with our regex pass (cheap and catches misuses)
    if Path(target).exists():
        regex_findings = await _run_container_scan_regex(target, exclude_dirs=exclude_dirs)
        findings.extend(_normalize_findings(regex_findings))

    if not used_real:
        slog.info("scan_engine_used", scan="container", engine="regex_fallback")

    return _normalize_findings(findings)


async def run_iac_scan(
    target: str,
    options: dict | None = None,
    exclude_dirs: list[str] | None = None,
) -> list[dict]:
    """IaC: Checkov → Terraform/K8s/CFN/Ansible regex fallback."""
    options = options or {}

    findings: list[dict] = []
    used_real = False

    checkov_results = await _engines.checkov_scan(target)
    if checkov_results is not None:
        findings.extend(checkov_results)
        used_real = True

    if not used_real:
        slog.info("scan_engine_used", scan="iac", engine="regex_fallback")
        regex_findings = await _run_iac_scan_regex(target, exclude_dirs=exclude_dirs)
        findings.extend(_normalize_findings(regex_findings))

    return _normalize_findings(findings)
