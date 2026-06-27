# AgentTrust

A trust protocol for autonomous AI agents — reputation, auditing, and graduated capability.

## Install

```bash
pip install agentrust
```

Or from source:

```bash
git clone https://github.com/cosmicfear/agentrust.git
cd agentrust
uv sync
```

## Usage

### Create an agent identity

```bash
agentrust init
```

Generates an Ed25519 key pair saved to `~/.agentrust/identity.json`. You get an `agent_id` like `agent_cef6deca5c5527b3`.

### Audit a skill

```bash
agentrust audit my_skill.py
```

Scans the Python file for dangerous patterns and outputs a signed audit report as JSON.

### Verify a report

```bash
agentrust audit my_skill.py > report.json
agentrust verify report.json
```

Checks the cryptographic signature and shows findings.

### View identity

```bash
agentrust status
```

## Protocol Spec

Read the full specification: [`PROTOCOL.md`](./PROTOCOL.md)

## Core Concepts

- **Agent Identity** — Ed25519 key pairs. Agent IDs are derived from the public key fingerprint.
- **Static Analysis** — AST-based scanner detects dangerous imports, shell execution, file system access, network calls, and obfuscation.
- **Signed Reports** — Every audit report is cryptographically signed. Tamper-proof by default.
- **Verification** — Anyone can verify a report using the publisher's public key. No server required.

## Design Principles

1. Trust is earned, not bought
2. Verify, don't trust
3. Distrust should be expensive
4. Time is the moat
5. Agents are first-class citizens

---

*Draft v0.1 — June 27, 2026*
