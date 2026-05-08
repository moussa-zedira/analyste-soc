"""Wordlist management routes for the pentest lab.

Provides endpoints to list, view, upload, and delete wordlists used
by the various pentest modules.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile

from apps.api.security import require_api_key
from apps.api.wordlists import builtin

router = APIRouter(dependencies=[Depends(require_api_key)])

# Directory where user-uploaded (custom) wordlists are stored.
_CUSTOM_DIR = Path(__file__).resolve().parent.parent / "wordlists" / "custom"
_CUSTOM_DIR.mkdir(parents=True, exist_ok=True)

# Map of built-in wordlist names to their Python objects.
_BUILTIN_MAP: dict[str, list[str]] = {
    "usernames": builtin.USERNAMES,
    "passwords": builtin.PASSWORDS,
    "directories": builtin.DIRECTORIES,
    "subdomains": builtin.SUBDOMAINS,
    "sqli": builtin.SQLI_PAYLOADS,
    "xss": builtin.XSS_PAYLOADS,
    "lfi": builtin.LFI_PAYLOADS,
    "commands": builtin.COMMAND_PAYLOADS,
}

# Allowed filename pattern for custom wordlists.
_NAME_RE = re.compile(r"^[a-zA-Z0-9_\-]+\.txt$")


def _custom_lists() -> dict[str, Path]:
    """Return a mapping of custom wordlist names to their file paths."""
    result: dict[str, Path] = {}
    if _CUSTOM_DIR.is_dir():
        for f in sorted(_CUSTOM_DIR.iterdir()):
            if f.is_file() and f.suffix == ".txt":
                result[f.stem] = f
    return result


# --------------------------------------------------------------------------
# GET /wordlists  — list available wordlists
# --------------------------------------------------------------------------
@router.get("")
def list_wordlists() -> dict[str, Any]:
    """Return all available wordlists (builtin + custom) with their sizes."""
    items: list[dict[str, Any]] = []

    for name, entries in _BUILTIN_MAP.items():
        items.append({
            "name": name,
            "type": "builtin",
            "count": len(entries),
        })

    for name, path in _custom_lists().items():
        line_count = sum(1 for _ in path.open(encoding="utf-8", errors="ignore"))
        items.append({
            "name": name,
            "type": "custom",
            "count": line_count,
        })

    return {"wordlists": items, "total": len(items)}


# --------------------------------------------------------------------------
# GET /wordlists/{name}  — get wordlist content
# --------------------------------------------------------------------------
@router.get("/{name}")
def get_wordlist(name: str) -> dict[str, Any]:
    """Return the content of a specific wordlist."""
    # Check builtin first.
    if name in _BUILTIN_MAP:
        entries = _BUILTIN_MAP[name]
        return {"name": name, "type": "builtin", "count": len(entries), "entries": entries}

    # Check custom.
    customs = _custom_lists()
    if name in customs:
        lines = [
            line.strip()
            for line in customs[name].read_text(encoding="utf-8", errors="ignore").splitlines()
            if line.strip()
        ]
        return {"name": name, "type": "custom", "count": len(lines), "entries": lines}

    raise HTTPException(status_code=404, detail=f"Wordlist '{name}' not found")


# --------------------------------------------------------------------------
# POST /wordlists/upload  — upload a custom wordlist
# --------------------------------------------------------------------------
@router.post("/upload")
async def upload_wordlist(file: UploadFile = File(...)) -> dict[str, Any]:
    """Upload a custom wordlist file (plain-text, one entry per line)."""
    filename = file.filename or "unnamed.txt"
    if not filename.endswith(".txt"):
        filename += ".txt"

    if not _NAME_RE.match(filename):
        raise HTTPException(
            status_code=400,
            detail="Invalid filename. Use only letters, digits, hyphens, and underscores.",
        )

    content = await file.read()
    if len(content) > 10 * 1024 * 1024:  # 10 MB cap
        raise HTTPException(status_code=413, detail="File too large (max 10 MB)")

    dest = _CUSTOM_DIR / filename
    dest.write_bytes(content)

    line_count = sum(1 for line in content.decode("utf-8", errors="ignore").splitlines() if line.strip())
    return {
        "name": dest.stem,
        "filename": filename,
        "count": line_count,
        "message": "Wordlist uploaded successfully",
    }


# --------------------------------------------------------------------------
# DELETE /wordlists/custom/{name}  — delete a custom wordlist
# --------------------------------------------------------------------------
@router.delete("/custom/{name}")
def delete_custom_wordlist(name: str) -> dict[str, str]:
    """Delete a custom wordlist by name."""
    customs = _custom_lists()
    if name not in customs:
        raise HTTPException(status_code=404, detail=f"Custom wordlist '{name}' not found")

    customs[name].unlink()
    return {"message": f"Custom wordlist '{name}' deleted successfully"}
