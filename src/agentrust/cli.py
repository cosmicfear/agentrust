"""AgentTrust CLI — init, audit, verify."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from agentrust.crypto import AgentIdentity
from agentrust.scanner import Finding, ScanResult, scan_file


AGENTRUST_DIR = Path.home() / ".agentrust"


def cmd_init() -> None:
    """Generate a new agent identity key pair."""
    identity = AgentIdentity.generate()

    AGENTRUST_DIR.mkdir(parents=True, exist_ok=True)
    identity_path = AGENTRUST_DIR / "identity.json"

    if identity_path.exists():
        print(f"Identity already exists at {identity_path}")
        print("Delete it first if you want to regenerate.")
        return

    identity.save(identity_path)
    print(f"agent_id: {identity.agent_id}")
    print(f"created:  {identity.created_at}")
    print(f"saved to: {identity_path}")
    print("\nThis identity is your agent's protocol-level account.")
    print("Keep identity.json safe — it controls your agent reputation.")


def cmd_audit(path: str) -> None:
    """Audit a skill file and produce a signed report."""
    skill_path = Path(path)
    if not skill_path.exists():
        print(f"Error: {path} not found")
        sys.exit(1)

    # Load identity
    identity_path = AGENTRUST_DIR / "identity.json"
    if not identity_path.exists():
        print("No identity found. Run 'agentrust init' first.")
        sys.exit(1)

    identity = AgentIdentity.load(identity_path)

    # Scan
    result = scan_file(skill_path)

    # Build report
    findings_json = [
        {"severity": f.severity, "description": f.description, "line": f.line}
        for f in result.findings
    ]

    report = {
        "agent_id": identity.agent_id,
        "skill_hash": result.skill_hash,
        "verdict": result.verdict,
        "confidence": result.confidence,
        "findings": findings_json,
        "timestamp": result.skill_hash  # placeholder, real timestamp below
    }

    # Rebuild with proper timestamp
    import time
    report["timestamp"] = int(time.time())

    # Sign
    report_bytes = json.dumps(report, sort_keys=True).encode()
    signature = identity.sign(report_bytes)

    report["signature"] = signature

    # Output — JSON to stdout (pipe-friendly), summary to stderr
    output = {
        "report": report,
        "public_key_pem": identity.public_key_pem,
    }

    print(json.dumps(output, indent=2))
    print(f"\n--- Verdict: {result.verdict} (confidence: {result.confidence}) ---",
          file=sys.stderr)


def cmd_verify(path: str) -> None:
    """Verify a signed audit report."""
    report_path = Path(path)
    if not report_path.exists():
        print(f"Error: {path} not found")
        sys.exit(1)

    data = json.loads(report_path.read_text())

    if isinstance(data, dict) and "report" in data:
        # Full output from audit command
        report = data["report"]
        public_key_pem = data.get("public_key_pem", "")
    else:
        report = data
        public_key_pem = ""

    signature = report.pop("signature", "")

    # Rebuild the canonical report bytes (sorted keys)
    report_bytes = json.dumps(report, sort_keys=True).encode()

    if not public_key_pem:
        print("No public key provided. Cannot verify signature.")
        print("Pass the full audit output (with public_key_pem) for verification.")
        return

    valid = AgentIdentity.verify_any(report_bytes, signature, public_key_pem)

    if valid:
        print("✓ SIGNATURE VALID")
    else:
        print("✗ SIGNATURE INVALID — report has been tampered with")

    print(f"Agent:     {report.get('agent_id', '?')}")
    print(f"Verdict:   {report.get('verdict', '?')}")
    print(f"Confidence: {report.get('confidence', '?')}")
    print(f"Skill:     {report.get('skill_hash', '?')}")
    print(f"Timestamp: {report.get('timestamp', '?')}")

    if report.get("findings"):
        print(f"\nFindings ({len(report['findings'])}):")
        for f in report["findings"]:
            print(f"  [{f['severity']}] line {f.get('line', '?')}: {f['description']}")


def cmd_status() -> None:
    """Show current identity status."""
    identity_path = AGENTRUST_DIR / "identity.json"
    if not identity_path.exists():
        print("No identity configured. Run 'agentrust init' first.")
        return

    identity = AgentIdentity.load(identity_path)
    print(f"agent_id:   {identity.agent_id}")
    print(f"created_at: {identity.created_at}")
    print(f"key_type:   Ed25519")
    print(f"identity:   {identity_path}")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="agentrust",
        description="AgentTrust — trust protocol for autonomous AI agents",
    )
    parser.add_argument(
        "--version", action="version", version="agentrust 0.1.0"
    )

    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init", help="Generate agent identity key pair")
    sub.add_parser("status", help="Show current identity")

    audit_p = sub.add_parser("audit", help="Audit a skill file")
    audit_p.add_argument("path", help="Path to the skill file (Python)")

    verify_p = sub.add_parser("verify", help="Verify a signed audit report")
    verify_p.add_argument("path", help="Path to the report JSON file")

    args = parser.parse_args()

    if args.command == "init":
        cmd_init()
    elif args.command == "status":
        cmd_status()
    elif args.command == "audit":
        cmd_audit(args.path)
    elif args.command == "verify":
        cmd_verify(args.path)


if __name__ == "__main__":
    main()
