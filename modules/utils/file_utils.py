"""
File utilities for FastAPI Doctor
"""
import os
from pathlib import Path
from typing import List, Tuple

def scan_tree(root: Path, skip_dirs: set) -> Tuple[List[Path], List[Path]]:
    """Parcourt l'arborescence une seule fois avec os.walk, en élaguant les répertoires."""
    all_paths: List[Path] = []
    py_paths: List[Path] = []
    for dirpath, dirnames, filenames in os.walk(root, topdown=True):
        dirnames[:] = [d for d in dirnames if d not in skip_dirs]
        dp = Path(dirpath)
        for name in filenames:
            p = dp / name
            all_paths.append(p)
            if p.suffix in (".py", ".pyi"):
                py_paths.append(p)
    return all_paths, py_paths

def read_all(paths: List[Path], limit: int = 5_000_000) -> dict[Path, str]:
    """Lit chaque fichier une seule fois et garde le résultat en mémoire."""
    result = {}
    for p in paths:
        try:
            if p.stat().st_size > limit:
                result[p] = ""
            else:
                result[p] = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            result[p] = ""
    return result

def is_dotenv_file(path: Path) -> bool:
    """Reconnaît .env et ses variantes (.env.local, .env.production, ...)."""
    name = path.name.lower()
    return name == ".env" or name.startswith(".env.")

def rel(path: Path, root: Path) -> str:
    """Retourne le chemin relatif par rapport à la racine."""
    try:
        return str(path.resolve().relative_to(root.resolve()))
    except ValueError:
        return str(path)

def read_text(path: Path, limit: int = 5_000_000) -> str:
    """Lit le contenu d'un fichier texte."""
    try:
        if path.stat().st_size > limit:
            return ""
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return ""


def is_test_path(path: Path, root: Path | None = None) -> bool:
    """Return True for conventional Python test files and directories."""
    try:
        candidate = path.relative_to(root) if root else path
    except ValueError:
        candidate = path
    parts = {part.lower() for part in candidate.parts}
    name = path.name.lower()
    return (
        bool(parts & {"test", "tests", "testing"})
        or name.startswith("test_")
        or name.endswith("_test.py")
        or name == "conftest.py"
    )
