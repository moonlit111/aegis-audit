from pathlib import Path


def read_document(root: str, name: str) -> str:
    """Read a document requested by a remote client from its documents directory."""
    directory = Path(root).resolve()
    target = (directory / name).resolve()
    target.relative_to(directory)
    return target.read_text(encoding="utf-8")
