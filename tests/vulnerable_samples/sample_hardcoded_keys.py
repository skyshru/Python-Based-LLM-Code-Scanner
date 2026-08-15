"""Intentionally vulnerable sample: hardcoded secrets and weak crypto.

This file exists only as scanner test input. All values are fake.
"""

import base64
import hashlib
import pickle

import requests

# CWE-798: credentials committed to source control.
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
STRIPE_SECRET_KEY = "sk_live_NOT_A_REAL_KEY_SCANNER_TEST_FIXTURE"
DATABASE_URL = "postgresql://admin:SuperSecret123@db.internal:5432/production"
JWT_SIGNING_SECRET = "changeme"


def hash_password(password: str) -> str:
    # CWE-327/CWE-916: unsalted MD5 for password storage.
    return hashlib.md5(password.encode()).hexdigest()


def verify_token(token: str) -> bool:
    # CWE-208: non-constant-time comparison of a secret.
    return base64.b64decode(token).decode() == JWT_SIGNING_SECRET


def fetch_internal_report(url: str):
    # CWE-295: TLS certificate verification disabled.
    return requests.get(url, verify=False, timeout=10).json()


def load_session(blob: bytes):
    # CWE-502: deserializing untrusted input yields RCE.
    return pickle.loads(blob)


def build_admin_policy():
    # CWE-732: wildcard IAM policy grants full account access.
    return {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}],
    }
