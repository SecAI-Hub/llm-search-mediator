"""
LLM Search Mediator - Privacy-preserving search bridge for local LLMs.

Sanitizes outbound queries (strips PII) and inbound results (strips HTML/scripts,
detects injection attempts, enforces size limits). All queries route through a
local SearXNG instance (optionally via Tor for anonymity).

The LLM never touches the network. This service is the only bridge between
inference and online information.
"""

import hmac
import html
import ipaddress
import json
import logging
import math
import os
import re
import secrets
import stat
import threading
import time
import unicodedata
from pathlib import Path
from urllib.parse import unquote, urlparse

import requests
import yaml
from flask import Flask, Response, jsonify, request
from werkzeug.exceptions import RequestEntityTooLarge

from .audit_chain import AuditChain

log = logging.getLogger("search-mediator")

app = Flask(__name__)
_privacy_random = secrets.SystemRandom()
_upstream_session = requests.Session()
# Do not let ambient HTTP(S)_PROXY variables redirect sensitive queries.
_upstream_session.trust_env = False

BIND_ADDR = os.getenv("BIND_ADDR", "127.0.0.1:8485")
SEARXNG_URL = os.getenv("SEARXNG_URL", "http://127.0.0.1:8888")
POLICY_PATH = os.getenv("POLICY_PATH", "")
AUDIT_DIR = os.getenv("AUDIT_DIR", "/var/lib/llm-search-mediator/logs")
SERVICE_TOKEN_PATH = os.getenv("SERVICE_TOKEN_PATH", "")

_audit_chain = AuditChain(os.path.join(AUDIT_DIR, "search-audit.jsonl"))

# Limits
MAX_SEARCH_BODY_BYTES = 16 * 1024
MAX_QUERY_LENGTH = 200
MAX_RESULTS = 5
MAX_SNIPPET_LENGTH = 500
MAX_CONTEXT_LENGTH = 4000
MAX_POLICY_BYTES = 1024 * 1024
MAX_UPSTREAM_BODY_BYTES = 2 * 1024 * 1024
MAX_RESULT_URL_LENGTH = 2048
DEFAULT_SEARCH_CATEGORIES = {"general"}
app.config["MAX_CONTENT_LENGTH"] = MAX_SEARCH_BODY_BYTES


class PolicyError(RuntimeError):
    """Raised when the search policy cannot be loaded or validated."""


_DEVELOPMENT_POLICY = {
    "version": 1,
    "search": {
        "enabled": True,
        "allowed_categories": ["general"],
        "differential_privacy": {
            "enabled": False,
            "decoy_count": 0,
            "uniqueness_mode": "auto-block",
            "batch_window": 0.0,
        },
    },
}

# Traffic analysis protection
def _bounded_delay_env(name: str, default: float) -> float:
    """Read a finite delay in the supported 0-30 second range."""
    try:
        value = float(os.getenv(name, str(default)))
    except (TypeError, ValueError):
        return default
    if not math.isfinite(value):
        return default
    return max(0.0, min(value, 30.0))


QUERY_DELAY_MIN = _bounded_delay_env("QUERY_DELAY_MIN", 0.5)
QUERY_DELAY_MAX = _bounded_delay_env("QUERY_DELAY_MAX", 3.0)
QUERY_PAD_BUCKETS = [256, 512, 1024]  # fixed-size query padding buckets (bytes)

# Differential privacy for search queries
DECOY_QUERIES = [
    "weather forecast today",
    "world news headlines",
    "popular recipes",
    "movie reviews 2026",
    "stock market update",
    "sports scores today",
    "technology news",
    "book recommendations",
    "travel destinations",
    "music new releases",
    "science discoveries",
    "health tips",
    "home improvement ideas",
    "gardening basics",
    "history facts",
    "programming tutorials",
    "fitness exercises",
    "cooking techniques",
    "photography tips",
    "language learning",
    "best restaurants near me",
    "how to change a tire",
    "local events this weekend",
    "job interview tips",
    "budget travel planning",
    "online learning platforms",
    "pet care advice",
    "diy crafts for beginners",
    "smartphone comparison 2026",
    "electric vehicle reviews",
    "climate change statistics",
    "space exploration news",
    "mental health resources",
    "investment strategies",
    "home workout routines",
    "organic food benefits",
    "renewable energy facts",
    "video game releases 2026",
    "interior design trends",
    "car maintenance schedule",
    "hiking trails nearby",
    "resume writing guide",
    "sleep improvement tips",
    "public transit schedules",
    "volunteer opportunities",
    "digital privacy guide",
    "meal prep ideas",
    "apartment hunting tips",
    "common houseplant care",
    "tax preparation help",
    "camping gear checklist",
    "first aid basics",
    "music theory fundamentals",
    "recycling guidelines",
    "time management techniques",
    "outdoor grilling recipes",
    "yoga for beginners",
    "home energy efficiency",
    "water conservation tips",
    "college application advice",
    "podcast recommendations",
    "bicycle maintenance",
    "coffee brewing methods",
    "board game suggestions",
    "seasonal allergy remedies",
    "mindfulness meditation",
    "weekend brunch ideas",
    "local library services",
    "skin care routine",
    "bird watching guide",
    "earthquake preparedness",
    "foreign currency exchange",
    "used car buying guide",
    "composting for beginners",
    "national park information",
    "free online courses",
    "home security systems",
    "holiday gift ideas",
    "effective study habits",
    "community garden programs",
]

# Words that make a query highly unique / identifying
RARE_QUERY_PATTERNS = [
    re.compile(r"\b[A-Z][a-z]+\s+[A-Z][a-z]+\b"),       # Proper names (First Last)
    re.compile(r"\b\d+\s+[A-Z][a-z]+\s+(?:St|Ave|Rd|Blvd|Dr|Ln|Ct)\b"),  # Street addresses
    re.compile(r"\b[A-Z]{2,}\s*-?\s*\d{3,}\b"),           # Case/ID numbers
    re.compile(r"\brare\s+disease\b", re.IGNORECASE),               # Rare medical terms
    re.compile(r"\bcase\s+(?:no|number|#)\s*\d+\b", re.IGNORECASE), # Case references
]

# Query generalization: keyword -> broader category term for cover traffic.
CATEGORY_KEYWORDS = {
    "treatment": "medical conditions",
    "symptom": "health information",
    "disease": "medical conditions",
    "diagnosis": "health information",
    "medication": "pharmaceutical information",
    "drug": "pharmaceutical information",
    "lawyer": "legal services",
    "attorney": "legal services",
    "lawsuit": "legal news",
    "court": "legal news",
    "salary": "employment statistics",
    "income": "financial planning",
    "debt": "financial planning",
    "invest": "financial news",
    "crypto": "financial news",
    "divorce": "family law",
    "custody": "family law",
    "arrest": "crime news",
    "criminal": "crime news",
    "immigration": "government services",
    "visa": "travel documents",
    "passport": "travel documents",
    "addiction": "health information",
    "rehab": "health information",
    "therapy": "mental health",
    "depression": "mental health",
    "anxiety": "mental health",
}

# Batch timing state
_batch_lock = threading.Lock()
_last_batch_time = 0.0

# ---------------------------------------------------------------------------
# Traffic analysis protection
# ---------------------------------------------------------------------------

def _validated_searxng_base_url() -> str:
    """Return a canonical operator-configured HTTP(S) SearXNG base URL."""
    raw_url = SEARXNG_URL.strip()
    if raw_url != SEARXNG_URL or len(raw_url.encode("utf-8")) > 2048:
        raise ValueError("SEARXNG_URL is padded or too long")
    if any(ord(character) < 0x20 or ord(character) == 0x7F for character in raw_url):
        raise ValueError("SEARXNG_URL contains control characters")
    parsed = urlparse(raw_url)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ValueError(
            "SEARXNG_URL must be an HTTP(S) origin without credentials or URL data"
        )
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("SEARXNG_URL contains an invalid port") from exc
    return raw_url.rstrip("/")


def _fixed_upstream_headers() -> dict[str, str]:
    """Return stable headers that do not forward caller or host identity."""
    return {
        "Accept": "application/json",
        "Accept-Encoding": "gzip, deflate",
        "Accept-Language": "en-US,en;q=0.9",
        "User-Agent": "SecAI-SearchMediator/1.0",
        "X-Forwarded-For": "127.0.0.1",
        "X-Real-IP": "127.0.0.1",
    }


def _upstream_get(
    endpoint: str,
    *,
    params: dict | None = None,
    timeout: float,
    expect_json: bool,
):
    """Call SearXNG without redirects, proxies, or unbounded response reads.

    JSON requests return a decoded object. Status-only requests return the HTTP
    status code and never consume a response body.
    """
    response = _upstream_session.get(
        f"{_validated_searxng_base_url()}{endpoint}",
        params=params,
        headers=_fixed_upstream_headers(),
        timeout=timeout,
        allow_redirects=False,
        stream=True,
    )
    if 300 <= response.status_code < 400:
        response.close()
        raise requests.RequestException("SearXNG redirects are not permitted")
    if not expect_json:
        status_code = response.status_code
        response.close()
        return status_code

    try:
        response.raise_for_status()
        raw = response.raw.read(MAX_UPSTREAM_BODY_BYTES + 1, decode_content=True)
        if len(raw) > MAX_UPSTREAM_BODY_BYTES:
            raise ValueError("SearXNG response exceeded the configured size limit")
        decoded = json.loads(raw.decode("utf-8", errors="strict"))
        if not isinstance(decoded, dict):
            raise TypeError("SearXNG response root must be an object")
        return decoded
    finally:
        response.close()


def _random_delay() -> float:
    """Sleep a random duration to decorrelate query timing."""
    minimum = max(0.0, min(QUERY_DELAY_MIN, 30.0))
    maximum = max(minimum, min(QUERY_DELAY_MAX, 30.0))
    delay = _privacy_random.uniform(minimum, maximum)
    time.sleep(delay)
    return delay


def pad_query(query: str) -> str:
    """Pad query to the next fixed-size bucket to obscure length patterns.

    Padding uses whitespace that SearXNG trims, so results are unaffected.
    Buckets: 256, 512, 1024 bytes.
    """
    encoded = query.encode("utf-8")
    query_len = len(encoded)

    target = QUERY_PAD_BUCKETS[-1]  # default to largest
    for bucket in QUERY_PAD_BUCKETS:
        if query_len <= bucket:
            target = bucket
            break

    if query_len >= target:
        return query  # already at or above largest bucket

    # Pad with spaces (SearXNG collapses whitespace)
    pad_len = target - query_len
    return query + (" " * pad_len)


# ---------------------------------------------------------------------------
# Differential privacy for search queries
# ---------------------------------------------------------------------------

def _load_dp_config(policy: dict | None = None) -> dict:
    """Return already-validated privacy settings from one policy snapshot."""
    validated = load_policy() if policy is None else policy
    return dict(validated["search"]["differential_privacy"])


def check_query_uniqueness(query: str) -> dict:
    """Check if a query is highly unique/identifying (k-anonymity risk).

    Returns:
        {"unique": bool, "matches": list of matched patterns}
    """
    matches = []
    for pattern in RARE_QUERY_PATTERNS:
        found = pattern.findall(query)
        if found:
            matches.extend(found)

    return {"unique": bool(matches), "matches": matches}


def generate_decoy_queries(count: int) -> list:
    """Select random decoy queries from the curated list."""
    if isinstance(count, bool) or not isinstance(count, int):
        return []
    count = max(0, min(count, len(DECOY_QUERIES)))
    return _privacy_random.sample(DECOY_QUERIES, count)


def send_decoy_search(query: str) -> None:
    """Fire-and-forget a decoy search to SearXNG. Results are discarded."""
    try:
        padded = pad_query(query)
        _upstream_get(
            "/search",
            params={
                "q": padded,
                "format": "json",
                "categories": "general",
                "language": "en",
                "safesearch": "1",
            },
            timeout=15,
            expect_json=False,
        )
        log.debug("decoy search sent: %d chars", len(query))
    except (requests.RequestException, OSError, UnicodeError, ValueError, TypeError):
        log.debug("decoy search failed", exc_info=True)


def run_decoy_searches(count: int) -> int:
    """Send decoy searches with random timing. Returns count sent."""
    decoys = generate_decoy_queries(count)
    for dq in decoys:
        delay = _privacy_random.uniform(0.2, 1.5)
        time.sleep(delay)
        send_decoy_search(dq)
    return len(decoys)


def generalize_query(query: str) -> str | None:
    """Return a broader category term for the query, or None if not needed."""
    query_lower = query.lower()
    for keyword, category in CATEGORY_KEYWORDS.items():
        if keyword in query_lower:
            return category
    return None


def send_cover_search(category_term: str) -> None:
    """Send a cover search for a broad category term. Results are discarded."""
    send_decoy_search(category_term)


def apply_batch_delay(batch_window: float) -> float:
    """Enforce batch timing: wait until at least *batch_window* seconds have
    elapsed since the last search, so queries are grouped into fixed windows.

    Returns the actual delay applied (0 if no wait was needed).
    """
    global _last_batch_time

    with _batch_lock:
        now = time.time()
        elapsed = now - _last_batch_time
        if elapsed < batch_window:
            wait = batch_window - elapsed
            time.sleep(wait)
            _last_batch_time = time.time()
            return wait
        else:
            _last_batch_time = now
            return 0.0


# ---------------------------------------------------------------------------
# PII patterns to strip from outbound queries
# ---------------------------------------------------------------------------

PII_PATTERNS = [
    (re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+"), "[EMAIL]"),
    (re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"), "[PHONE]"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[SSN]"),
    (re.compile(r"\b(?:\d{4}[-\s]?){3}\d{4}\b"), "[CARD]"),
    (re.compile(r"\b(?:account|acct)[\s:#-]*\d{6,17}\b", re.IGNORECASE), "[BANK_ACCOUNT]"),
    (re.compile(r"\b(?:routing|aba)[\s:#-]*\d{9}\b", re.IGNORECASE), "[ROUTING]"),
    (re.compile(r"\b(?:passport)[\s:#-]*[A-Z0-9]{6,12}\b", re.IGNORECASE), "[PASSPORT]"),
    (re.compile(r"\b\d{1,6}\s+[A-Za-z0-9.'-]+(?:\s+[A-Za-z0-9.'-]+)*\s+(?:St|Street|Ave|Avenue|Rd|Road|Blvd|Drive|Dr|Lane|Ln|Court|Ct)\b", re.IGNORECASE), "[ADDRESS]"),
    (re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b"), "[IP]"),
    (re.compile(r"\b(?:born|dob|birthday)[:\s]+\d{1,2}[/\-]\d{1,2}[/\-]\d{2,4}\b", re.IGNORECASE), "[DOB]"),
    (re.compile(r"\b(?:sk-|pk-|api[_-]?key[:\s=]+)[a-zA-Z0-9]{20,}\b", re.IGNORECASE), "[API_KEY]"),
    (re.compile(r"\b[a-fA-F0-9]{32,}\b"), "[HEX_TOKEN]"),
]

# Patterns that suggest prompt injection in search results
INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(?:all\s+)?(?:previous|above|prior)\s+instructions", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(?:a|an|in)\s+", re.IGNORECASE),
    re.compile(r"system\s*prompt\s*:", re.IGNORECASE),
    re.compile(r"<\s*(?:script|iframe|object|embed)", re.IGNORECASE),
    re.compile(r"javascript\s*:", re.IGNORECASE),
    re.compile(r"data\s*:\s*text/html", re.IGNORECASE),
]

# HTML tag stripper
HTML_TAG_RE = re.compile(r"<[^>]+>")
MULTI_SPACE_RE = re.compile(r"\s+")
HIGH_RISK_PLACEHOLDERS = {
    "[SSN]",
    "[CARD]",
    "[BANK_ACCOUNT]",
    "[ROUTING]",
    "[PASSPORT]",
    "[API_KEY]",
    "[HEX_TOKEN]",
}


def _read_service_token() -> str:
    """Read a bounded token without following symlinks."""
    token = os.getenv("SERVICE_TOKEN", "")
    if token:
        return token if _valid_service_token(token) else ""
    token_path = os.getenv("SERVICE_TOKEN_PATH", SERVICE_TOKEN_PATH).strip()
    if token_path:
        descriptor = -1
        try:
            descriptor = os.open(
                token_path,
                os.O_RDONLY
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0),
            )
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_nlink != 1
                or metadata.st_mode & 0o077
                or metadata.st_uid not in {0, os.geteuid()}
                or not 32 <= metadata.st_size <= 4096
            ):
                return ""
            raw = os.read(descriptor, 4097)
            if len(raw) != metadata.st_size:
                return ""
            decoded = raw.decode("utf-8", errors="strict")
            return decoded if _valid_service_token(decoded) else ""
        except (OSError, UnicodeDecodeError):
            return ""
        finally:
            if descriptor >= 0:
                os.close(descriptor)
    return ""


def _valid_service_token(token: str) -> bool:
    """Require a bounded, control-free token with at least 256 bits of material."""
    try:
        encoded = token.encode("utf-8", errors="strict")
    except UnicodeError:
        return False
    return (
        32 <= len(encoded) <= 4096
        and all(0x21 <= octet <= 0x7E for octet in encoded)
    )


def _insecure_loopback_dev_auth_allowed() -> bool:
    if os.getenv("SECAI_ALLOW_INSECURE_NO_AUTH") != "1":
        return False
    try:
        host, _port = BIND_ADDR.rsplit(":", 1)
        host = host.strip("[]")
        return host == "localhost" or ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _require_service_token() -> tuple[bool, Response | None]:
    """Authenticate egress-capable endpoints and fail closed by default."""
    token = _read_service_token()
    if not token:
        if _insecure_loopback_dev_auth_allowed():
            log.warning("explicit loopback-only insecure authentication mode is active")
            return True, None
        return False, (jsonify({"error": "service authentication unavailable"}), 503)
    auth = request.headers.get("Authorization", "")
    prefix = "Bearer "
    if not auth.startswith(prefix):
        return False, (jsonify({"error": "forbidden"}), 403)
    if not hmac.compare_digest(auth[len(prefix):], token):
        return False, (jsonify({"error": "forbidden"}), 403)
    return True, None


def _validate_policy(policy: object) -> dict:
    """Validate the complete versioned policy and return a normalized copy."""
    if not isinstance(policy, dict) or set(policy) != {"version", "search"}:
        raise PolicyError("policy must contain only version and search")
    if policy["version"] != 1 or isinstance(policy["version"], bool):
        raise PolicyError("unsupported policy version")

    search = policy["search"]
    required_search_keys = {
        "enabled",
        "allowed_categories",
        "differential_privacy",
    }
    if not isinstance(search, dict) or set(search) != required_search_keys:
        raise PolicyError("search policy schema is invalid")
    if not isinstance(search["enabled"], bool):
        raise PolicyError("search.enabled must be a boolean")

    categories = search["allowed_categories"]
    if (
        not isinstance(categories, list)
        or not categories
        or len(categories) > 32
        or len(categories) != len(set(categories))
        or any(
            not isinstance(item, str)
            or re.fullmatch(r"[a-z][a-z0-9_-]{0,31}", item) is None
            for item in categories
        )
    ):
        raise PolicyError("search.allowed_categories is invalid")

    dp = search["differential_privacy"]
    required_dp_keys = {
        "enabled",
        "decoy_count",
        "uniqueness_mode",
        "batch_window",
    }
    if not isinstance(dp, dict) or set(dp) != required_dp_keys:
        raise PolicyError("differential_privacy policy schema is invalid")
    if not isinstance(dp["enabled"], bool):
        raise PolicyError("differential_privacy.enabled must be a boolean")
    decoy_count = dp["decoy_count"]
    if isinstance(decoy_count, bool) or not isinstance(decoy_count, int):
        raise PolicyError("differential_privacy.decoy_count must be an integer")
    if not 0 <= decoy_count <= 10:
        raise PolicyError("differential_privacy.decoy_count is out of range")
    uniqueness_mode = dp["uniqueness_mode"]
    if uniqueness_mode not in {"auto-block", "warn", "allow"}:
        raise PolicyError("differential_privacy.uniqueness_mode is invalid")
    batch_window = dp["batch_window"]
    if (
        isinstance(batch_window, bool)
        or not isinstance(batch_window, (int, float))
        or not math.isfinite(float(batch_window))
        or not 0.0 <= float(batch_window) <= 30.0
    ):
        raise PolicyError("differential_privacy.batch_window is invalid")

    return {
        "version": 1,
        "search": {
            "enabled": search["enabled"],
            "allowed_categories": list(categories),
            "differential_privacy": {
                "enabled": dp["enabled"],
                "decoy_count": decoy_count,
                "uniqueness_mode": uniqueness_mode,
                "batch_window": float(batch_window),
            },
        },
    }


def load_policy() -> dict:
    """Atomically load and strictly validate one bounded policy snapshot."""
    if not POLICY_PATH:
        if _insecure_loopback_dev_auth_allowed():
            return _validate_policy(_DEVELOPMENT_POLICY)
        raise PolicyError("POLICY_PATH is not configured")
    descriptor = -1
    try:
        path = Path(POLICY_PATH)
        descriptor = os.open(
            path,
            os.O_RDONLY
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
            | getattr(os, "O_NONBLOCK", 0),
        )
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISREG(metadata.st_mode)
            or metadata.st_nlink != 1
            or metadata.st_mode & 0o022
            or not 1 <= metadata.st_size <= MAX_POLICY_BYTES
        ):
            raise ValueError("policy is not a secure bounded regular file")
        raw = os.read(descriptor, MAX_POLICY_BYTES + 1)
        if len(raw) != metadata.st_size:
            raise ValueError("policy changed while it was being read")
        policy = yaml.safe_load(raw.decode("utf-8", errors="strict"))
        return _validate_policy(policy)
    except (OSError, UnicodeError, TypeError, ValueError, yaml.YAMLError) as exc:
        log.error("policy unavailable or invalid")
        raise PolicyError("policy unavailable or invalid") from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)


def _is_search_enabled(policy: dict | None = None) -> bool:
    """Check if web search is enabled in policy."""
    validated = load_policy() if policy is None else policy
    return validated["search"]["enabled"]


def _allowed_categories(policy: dict | None = None) -> set[str]:
    validated = load_policy() if policy is None else policy
    return set(validated["search"]["allowed_categories"])


# ---------------------------------------------------------------------------
# Query sanitization (outbound)
# ---------------------------------------------------------------------------

def sanitize_query(raw_query: str) -> dict:
    """Strip PII and sensitive data from an outbound search query.

    Returns:
        {"query": sanitized_string, "redactions": [...], "blocked": bool, "reason": str}
    """
    if not isinstance(raw_query, str) or not raw_query.strip():
        return {"query": "", "redactions": [], "blocked": True, "reason": "empty query"}

    query = raw_query.strip()

    redactions = []
    for pattern, replacement in PII_PATTERNS:
        matches = pattern.findall(query)
        if matches:
            redactions.extend(matches)
            query = pattern.sub(replacement, query)

    high_risk_count = sum(query.count(placeholder) for placeholder in HIGH_RISK_PLACEHOLDERS)
    if high_risk_count >= 2:
        return {
            "query": query,
            "redactions": redactions,
            "blocked": True,
            "reason": "query contains multiple high-risk identifiers",
        }

    # If the query is mostly redacted, block it
    tokens = query.split()
    redacted_tokens = sum(1 for t in tokens if t.startswith("[") and t.endswith("]"))
    if tokens and redacted_tokens / len(tokens) > 0.5:
        return {
            "query": query,
            "redactions": redactions,
            "blocked": True,
            "reason": "query contains too much PII",
        }

    # Scan the entire request-bounded input before enforcing the outbound limit.
    # Reject instead of truncating so PII at the boundary cannot be discarded
    # before inspection or accidentally split into an unrecognized fragment.
    if len(query) > MAX_QUERY_LENGTH:
        return {
            "query": "",
            "redactions": redactions,
            "blocked": True,
            "reason": "query exceeds maximum length",
        }

    return {"query": query, "redactions": redactions, "blocked": False, "reason": ""}


# ---------------------------------------------------------------------------
# Result sanitization (inbound)
# ---------------------------------------------------------------------------

def sanitize_snippet(raw_text: str) -> str:
    """Clean a search result snippet: strip HTML, decode entities, remove injection."""
    if not isinstance(raw_text, str) or not raw_text:
        return ""

    text = HTML_TAG_RE.sub(" ", raw_text)
    text = html.unescape(text)
    text = unicodedata.normalize("NFKC", text)
    # Remove controls, bidi overrides, zero-width format characters, and
    # unpaired surrogates before pattern matching and JSON serialization.
    text = "".join(
        " " if unicodedata.category(character).startswith("C") else character
        for character in text
    )
    text = MULTI_SPACE_RE.sub(" ", text).strip()
    if len(text) > MAX_SNIPPET_LENGTH:
        text = text[:MAX_SNIPPET_LENGTH] + "..."

    return text


def check_injection(text: str) -> bool:
    """Return True if text contains suspected prompt injection."""
    for pattern in INJECTION_PATTERNS:
        if pattern.search(text):
            return True
    return False


def sanitize_results(raw_results: list) -> list:
    """Sanitize a list of search results from SearXNG."""
    if not isinstance(raw_results, list):
        return []
    clean = []
    for r in raw_results[:MAX_RESULTS]:
        if not isinstance(r, dict):
            continue
        title = sanitize_snippet(r.get("title", ""))
        snippet = sanitize_snippet(r.get("content", ""))
        url = r.get("url", "")

        try:
            if not isinstance(url, str) or len(url.encode("utf-8")) > MAX_RESULT_URL_LENGTH:
                raise ValueError("invalid URL")
            decoded_url = unquote(url)
            if (
                "\\" in decoded_url
                or any(character.isspace() for character in url)
                or any(
                    unicodedata.category(character).startswith("C")
                    for character in decoded_url
                )
            ):
                raise ValueError("invalid URL")
            parsed = urlparse(url)
            if (
                parsed.scheme not in ("http", "https")
                or not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
            ):
                raise ValueError("invalid URL")
            _ = parsed.port
        except (TypeError, UnicodeError, ValueError):
            url = ""

        if check_injection(title) or check_injection(snippet):
            log.warning("injection detected in result from %s, skipping", url)
            continue

        if title or snippet:
            clean.append({
                "title": title,
                "snippet": snippet,
                "url": url,
                "source": parsed.hostname if url else "unknown",
            })

    return clean


def build_context(results: list) -> str:
    """Build a context string from sanitized results for the LLM."""
    if not results:
        return ""

    parts = ["The following information was retrieved from web search:\n"]
    for i, r in enumerate(results, 1):
        parts.append(f"[{i}] {r['title']}")
        if r["snippet"]:
            parts.append(f"    {r['snippet']}")
        if r["url"]:
            parts.append(f"    Source: {r['url']}")
        parts.append("")

    context = "\n".join(parts)
    if len(context) > MAX_CONTEXT_LENGTH:
        context = context[:MAX_CONTEXT_LENGTH] + "\n[... truncated for length]"

    return context


# ---------------------------------------------------------------------------
# Audit logging
# ---------------------------------------------------------------------------

def audit_search(query: str, redactions: list, num_results: int, blocked: bool):
    """Write a hash-chained audit record for every search attempt."""
    _audit_chain.append("web_search", {
        "query_length": len(query),
        "redactions_count": len(redactions),
        "results_returned": num_results,
        "blocked": blocked,
    })


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.errorhandler(RequestEntityTooLarge)
def request_too_large(_error):
    """Return a stable JSON response for declared and streamed oversized bodies."""
    return jsonify({"error": "request body too large"}), 413

@app.route("/health")
def health():
    authenticated, auth_error = _require_service_token()
    if not authenticated:
        return auth_error

    try:
        policy = load_policy()
    except PolicyError:
        return jsonify({
            "status": "degraded",
            "search_enabled": False,
            "searxng_reachable": False,
            "error": "service policy unavailable",
        }), 503

    enabled = _is_search_enabled(policy)

    searxng_ok = False
    if enabled:
        try:
            status_code = _upstream_get(
                "/healthz",
                timeout=3,
                expect_json=False,
            )
            searxng_ok = status_code == 200
        except (requests.RequestException, OSError, ValueError):
            log.warning("SearXNG readiness probe failed")

    return jsonify({
        "status": "ok",
        "search_enabled": enabled,
        "searxng_reachable": searxng_ok,
    })


@app.route("/live")
def live():
    """Process liveness must not depend on the optional upstream service."""
    return jsonify({"status": "ok"})


@app.route("/v1/search", methods=["POST"])
def search():
    """Perform a sanitized web search."""

    authenticated, auth_error = _require_service_token()
    if not authenticated:
        return auth_error

    if request.content_length and request.content_length > MAX_SEARCH_BODY_BYTES:
        return jsonify({"error": "request body too large"}), 413

    try:
        policy = load_policy()
    except PolicyError:
        return jsonify({"error": "service policy unavailable"}), 503

    if not _is_search_enabled(policy):
        return jsonify({"error": "web search is disabled in policy"}), 403

    body = request.get_json(silent=True)
    if not isinstance(body, dict):
        return jsonify({"error": "JSON object body required"}), 400

    raw_query = body.get("query", "")
    categories = body.get("categories", "general")
    if not isinstance(raw_query, str):
        return jsonify({"error": "query must be a string"}), 400
    if not isinstance(categories, str) or categories not in _allowed_categories(policy):
        return jsonify({"error": "search category is not allowed"}), 400

    # Sanitize the outbound query
    san = sanitize_query(raw_query)
    if san["blocked"]:
        audit_search(raw_query, san["redactions"], 0, True)
        return jsonify({
            "error": f"query blocked: {san['reason']}",
            "redactions": len(san["redactions"]),
        }), 422

    # Differential privacy checks
    dp_config = _load_dp_config(policy)
    uniqueness_warning = None
    decoys_sent = 0

    if dp_config["enabled"]:
        uq = check_query_uniqueness(san["query"])
        if uq["unique"]:
            mode = dp_config["uniqueness_mode"]
            if mode == "auto-block":
                audit_search(raw_query, san["redactions"], 0, True)
                return jsonify({
                    "error": "query blocked: contains highly unique/identifying terms",
                    "unique_match_count": len(uq["matches"]),
                }), 422
            elif mode == "warn":
                uniqueness_warning = (
                    "This query contains potentially identifying terms"
                )
                log.warning(
                    "unique query detected (warn mode; matches=%d)",
                    len(uq["matches"]),
                )

        category = generalize_query(san["query"])
        if category:
            log.debug("cover search for category: %s", category)
            send_cover_search(category)

        decoys_sent = run_decoy_searches(dp_config["decoy_count"])
        apply_batch_delay(dp_config["batch_window"])

    # Traffic analysis protection: random delay
    delay = _random_delay()

    # Pad query to fixed-size bucket
    padded_query = pad_query(san["query"])

    # Query SearXNG
    try:
        data = _upstream_get(
            "/search",
            params={
                "q": padded_query,
                "format": "json",
                "categories": categories,
                "language": "en",
                "safesearch": "1",
            },
            timeout=30,
            expect_json=True,
        )
    except requests.Timeout:
        audit_search(raw_query, san["redactions"], 0, False)
        return jsonify({"error": "search timed out"}), 504
    except (
        requests.RequestException,
        OSError,
        UnicodeError,
        TypeError,
        ValueError,
        json.JSONDecodeError,
    ):
        log.exception("SearXNG request failed")
        audit_search(raw_query, san["redactions"], 0, False)
        return jsonify({"error": "search upstream unavailable"}), 502

    raw_results = data.get("results", [])
    clean_results = sanitize_results(raw_results)
    context = build_context(clean_results)

    audit_search(raw_query, san["redactions"], len(clean_results), False)

    log.info("search completed: query_len=%d results=%d redactions=%d delay=%.2fs decoys=%d",
             len(san["query"]), len(clean_results), len(san["redactions"]), delay, decoys_sent)

    result = {
        "results": clean_results,
        "context": context,
        "query_used": san["query"],
        "redactions": len(san["redactions"]),
        "decoys_sent": decoys_sent,
    }
    if uniqueness_warning:
        result["uniqueness_warning"] = uniqueness_warning

    return jsonify(result)


@app.route("/v1/search/test", methods=["GET"])
def search_test():
    """Quick connectivity test: verify SearXNG is reachable."""
    authenticated, auth_error = _require_service_token()
    if not authenticated:
        return auth_error

    try:
        policy = load_policy()
    except PolicyError:
        return jsonify({"error": "service policy unavailable"}), 503

    if not _is_search_enabled(policy):
        return jsonify({"error": "web search is disabled"}), 403

    try:
        status_code = _upstream_get(
            "/search",
            params={"q": "test", "format": "json"},
            timeout=30,
            expect_json=False,
        )
        return jsonify({
            "status": "ok",
            "searxng_status": status_code,
        })
    except (requests.RequestException, OSError, ValueError):
        log.warning("SearXNG connectivity test failed")
        return jsonify({
            "status": "error",
            "error": "search upstream unavailable",
        }), 502


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )
    host, port = BIND_ADDR.rsplit(":", 1)
    log.info("llm-search-mediator starting on %s (SearXNG=%s)", BIND_ADDR, SEARXNG_URL)
    app.run(host=host, port=int(port), debug=False, threaded=True)


if __name__ == "__main__":
    main()
