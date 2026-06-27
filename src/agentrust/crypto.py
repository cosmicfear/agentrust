"""Agent identity and cryptographic operations."""

from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


@dataclass
class AgentIdentity:
    """An agent's cryptographic identity."""

    agent_id: str
    public_key_pem: str

    # Only present on the generating machine
    private_key_pem: str = field(repr=False)

    created_at: int = 0

    @classmethod
    def generate(cls) -> AgentIdentity:
        """Generate a fresh Ed25519 key pair and derive agent ID."""
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()

        priv_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode()

        pub_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()

        fingerprint = hashlib.sha256(pub_pem.encode()).hexdigest()[:16]
        agent_id = f"agent_{fingerprint}"

        return cls(
            agent_id=agent_id,
            public_key_pem=pub_pem,
            private_key_pem=priv_pem,
            created_at=int(time.time()),
        )

    @classmethod
    def load(cls, path: Path) -> AgentIdentity:
        """Load identity from a JSON file."""
        data = json.loads(path.read_text())
        return cls(**data)

    def save(self, path: Path) -> None:
        """Save identity to a JSON file."""
        path.write_text(json.dumps(self.__dict__, indent=2))

    def sign(self, payload: bytes) -> str:
        """Sign arbitrary bytes with the private key. Returns base64 signature."""
        private_key = serialization.load_pem_private_key(
            self.private_key_pem.encode(), password=None
        )
        assert isinstance(private_key, Ed25519PrivateKey)
        sig = private_key.sign(payload)
        return base64.b64encode(sig).decode()

    def verify(self, payload: bytes, signature_b64: str) -> bool:
        """Verify a base64 signature against the payload using the stored public key."""
        try:
            public_key = serialization.load_pem_public_key(
                self.public_key_pem.encode()
            )
            assert isinstance(public_key, Ed25519PublicKey)
            public_key.verify(base64.b64decode(signature_b64), payload)
            return True
        except (InvalidSignature, Exception):
            return False

    @classmethod
    def verify_any(
        cls, payload: bytes, signature_b64: str, public_key_pem: str
    ) -> bool:
        """Static verify using an arbitrary public key (no identity loaded)."""
        try:
            public_key = serialization.load_pem_public_key(
                public_key_pem.encode()
            )
            assert isinstance(public_key, Ed25519PublicKey)
            public_key.verify(base64.b64decode(signature_b64), payload)
            return True
        except (InvalidSignature, Exception):
            return False
