"""Environment-configured reviewer authentication for the local console."""

import hashlib
import hmac
import json
import os


from dataclasses import dataclass


@dataclass(frozen=True)
class AuthenticatedReviewer:
	reviewer_id: str
	role: str


def make_password_hash(password: str, salt: str = "sentinel") -> str:
	derived = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 200_000).hex()
	return f"{salt}${derived}"


def _users() -> dict[str, dict[str, str]]:
	try:
		data = json.loads(os.environ.get("SENTINEL_USERS", "{}"))
		if not isinstance(data, dict):
			raise ValueError("SENTINEL_USERS must be a JSON object")
		return data
	except json.JSONDecodeError as error:
		raise ValueError("SENTINEL_USERS must be valid JSON") from error


def authenticate(reviewer_id: str, password: str) -> AuthenticatedReviewer | None:
	user = _users().get(reviewer_id.strip())
	if not isinstance(user, dict):
		return None
	stored_hash = user.get("password_hash", "")
	salt, _, expected = stored_hash.partition("$")
	if not salt or not expected:
		return None
	candidate = make_password_hash(password, salt)
	if not hmac.compare_digest(candidate, stored_hash):
		return None
	return AuthenticatedReviewer(reviewer_id.strip(), user.get("role", ""))
