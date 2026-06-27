"""Static analysis scanner for Python skills.

For the MVP, this checks for common dangerous patterns.
In production, this would be replaced by agent-driven audit agents.
"""

from __future__ import annotations

import ast
import hashlib
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import List


@dataclass
class Finding:
    severity: str  # "low" | "medium" | "high" | "critical"
    description: str
    line: int = 0


@dataclass
class ScanResult:
    verdict: str  # "CLEAN" | "FLAGGED" | "MALICIOUS"
    confidence: float
    findings: List[Finding] = field(default_factory=list)
    skill_hash: str = ""


# Dangerous patterns — things a skill absolutely shouldn't do
DANGEROUS_CALLS: dict[str, str] = {
    "os.system": "Shell command execution",
    "os.popen": "Shell command execution",
    "subprocess.run": "External process execution",
    "subprocess.Popen": "External process execution",
    "subprocess.call": "External process execution",
    "subprocess.check_output": "External process execution",
    "eval": "Arbitrary code evaluation",
    "exec": "Arbitrary code execution",
    "compile": "Dynamic code compilation",
    "__import__": "Dynamic import (possible code execution)",
    "execfile": "Deprecated file execution",
}

HIGH_RISK_IMPORTS: list[str] = [
    "ctypes", "fcntl", "mmap", "ptty", "pwd", "grp",
    "crypt", "cryptography.hazmat", "winreg", "ctypes.wintypes",
]

FILE_ACCESS_PATTERNS: list[tuple[str, str]] = [
    (r'open\(["\']/(etc|proc|sys|boot|dev)', "Read from system path"),
    (r'open\(["\'].*passwd', "Attempt to read password file"),
    (r'open\(["\'].*\.ssh', "Attempt to access SSH keys"),
    (r'open\(["\'].*config.*\.(json|yaml|toml|ini|env)', "Read config file"),
    (r'open\(["\'].*\.git/config', "Attempt to read git config"),
]

NETWORK_PATTERNS: list[str] = [
    "requests.get", "requests.post", "requests.put", "requests.delete",
    "urllib.request", "urllib.parse",
    "http.client", "socket.socket",
    "aiohttp.ClientSession",
    "httpx.Client", "httpx.AsyncClient",
]


def _ast_scan(source: str) -> list[Finding]:
    """Parse source as AST and look for dangerous patterns."""
    findings: list[Finding] = []

    try:
        tree = ast.parse(source)
    except SyntaxError:
        return [Finding("high", "Invalid Python syntax — possible obfuscation", 0)]

    for node in ast.walk(tree):
        # Check direct function calls
        if isinstance(node, ast.Call):
            func_name = _get_call_name(node)
            if func_name in DANGEROUS_CALLS:
                findings.append(
                    Finding("critical", DANGEROUS_CALLS[func_name], node.lineno or 0)
                )

        # Check imports
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in HIGH_RISK_IMPORTS:
                    findings.append(
                        Finding("high", f"High-risk import: {alias.name}", node.lineno or 0)
                    )
                if alias.name == "os":
                    findings.append(
                        Finding("medium", "os module imported — review required", node.lineno or 0)
                    )

        if isinstance(node, ast.ImportFrom):
            module = node.module or ""
            for alias in node.names:
                full_import = f"{module}.{alias.name}" if module else alias.name
                if full_import in DANGEROUS_CALLS or alias.name in DANGEROUS_CALLS:
                    findings.append(
                        Finding("critical", DANGEROUS_CALLS.get(full_import, "Suspicious import"),
                                node.lineno or 0)
                    )
                if module in HIGH_RISK_IMPORTS:
                    findings.append(
                        Finding("high", f"High-risk import from: {module}", node.lineno or 0)
                    )

        # Check string obfuscation
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            if len(node.value) > 200 and any(c in node.value for c in "\\x\\u\\U\\"):
                findings.append(
                    Finding("high", "Suspicious encoded string (>200 chars with escape sequences)",
                            node.lineno or 0)
                )
            if "base64" in node.value.lower() and len(node.value) > 50:
                findings.append(
                    Finding("medium", "Possible base64-encoded payload", node.lineno or 0)
                )

    return findings


def _regex_scan(source: str) -> list[Finding]:
    """Text-based regex scanning for patterns AST might miss."""
    findings: list[Finding] = []

    # File access patterns
    for pattern, description in FILE_ACCESS_PATTERNS:
        matches = list(re.finditer(pattern, source, re.MULTILINE))
        for m in matches:
            line_no = source[: m.start()].count("\n") + 1
            findings.append(Finding("high", description, line_no))

    # Network calls
    for net_call in NETWORK_PATTERNS:
        matches = list(re.finditer(re.escape(net_call), source))
        for m in matches:
            line_no = source[: m.start()].count("\n") + 1
            findings.append(Finding("medium", f"Network call detected: {net_call}", line_no))

    return findings


def _get_call_name(node: ast.Call) -> str:
    """Get the full dotted name of a call node (e.g., 'os.system')."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        parts = []
        current = node.func
        while isinstance(current, ast.Attribute):
            parts.append(current.attr)
            current = current.value
        if isinstance(current, ast.Name):
            parts.append(current.id)
        return ".".join(reversed(parts))
    return ""


def scan_file(path: Path) -> ScanResult:
    """Scan a Python file for dangerous patterns. Returns a scan result."""
    source = path.read_text(encoding="utf-8", errors="replace")

    # Hash the source
    skill_hash = "sha256:" + hashlib.sha256(source.encode()).hexdigest()

    findings = _ast_scan(source) + _regex_scan(source)

    # Determine verdict
    severities = [f.severity for f in findings]
    criticals = severities.count("critical")
    highs = severities.count("high")
    mediums = severities.count("medium")

    if criticals > 0:
        verdict = "MALICIOUS"
        confidence = 0.95
    elif highs >= 3:
        verdict = "MALICIOUS"
        confidence = 0.85
    elif highs > 0:
        verdict = "FLAGGED"
        confidence = 0.75
    elif mediums > 3:
        verdict = "FLAGGED"
        confidence = 0.60
    else:
        verdict = "CLEAN"
        confidence = 0.90

    return ScanResult(
        verdict=verdict,
        confidence=confidence,
        findings=findings,
        skill_hash=skill_hash,
    )
