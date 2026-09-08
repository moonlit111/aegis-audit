from pathlib import Path


def read_document(root: str, name: str) -> str:
    """Read a document requested by a remote client from its documents directory."""
    return (Path(root) / name).read_text(encoding="utf-8")
