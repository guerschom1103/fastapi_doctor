"""French labels for diagnostics produced by built-in analyzers."""
from __future__ import annotations

from typing import Any


CATEGORIES = {
    "Async Performance": "Performance async",
    "Async Correctness": "Correction async",
    "Data Flow": "Flux de données",
    "Code Quality": "Qualité du code",
    "Type Safety": "Typage",
    "FastAPI Documentation": "Documentation FastAPI",
    "FastAPI Security": "Sécurité FastAPI",
    "SQL Injection": "Injection SQL",
    "Testing": "Tests",
    "Tooling": "Outillage",
}

TEXT = {
    "Potential N+1 query pattern": "Requête N+1 potentielle",
    "Database query detected inside a loop (N+1 problem).": "Une requête de base de données semble être exécutée dans une boucle.",
    "Use eager loading (JOINs) or batch queries to avoid N+1.": "Utiliser un chargement groupé ou une jointure si plusieurs requêtes sont réellement exécutées.",
    "Concrete dependency import": "Import d'une implémentation concrète",
    "Importing concrete implementation instead of interface.": "Une implémentation concrète est importée directement.",
    "Use dependency injection and program to interfaces.": "Vérifier si une abstraction améliorerait réellement le découplage.",
    "High coupling (many imports)": "Couplage élevé (nombreux imports)",
    "Reduce dependencies and apply dependency inversion.": "Réexaminer les responsabilités du module et réduire les dépendances si nécessaire.",
    "Nested async function": "Fonction async imbriquée",
    "Consider moving nested async functions to module level.": "La déplacer au niveau du module uniquement si elle ne capture pas d'état local.",
    "Inefficient list operation in loop": "Opération de liste potentiellement coûteuse dans une boucle",
    "List creation or extension detected inside a loop.": "Une création ou extension de liste a été détectée dans une boucle.",
    "Pre-allocate lists or use list comprehensions when possible.": "Vérifier avec une mesure de performance avant toute optimisation.",
    "Swagger UI disabled": "Interface Swagger désactivée",
    "Swagger UI documentation appears to be disabled.": "L'interface Swagger semble désactivée.",
    "ReDoc disabled": "Interface ReDoc désactivée",
    "ReDoc documentation appears to be disabled.": "L'interface ReDoc semble désactivée.",
    "Route without explicit security": "Route sans sécurité explicite",
    "Circular dependency detected": "Dépendance circulaire détectée",
    "Circular import detected": "Import circulaire détecté",
    "Potential God class": "Classe potentiellement trop volumineuse",
    "Mixed concerns in file": "Responsabilités potentiellement mélangées",
    "Database logic in API layer": "Logique de base de données dans la couche API",
    "Clean Architecture violation": "Écart potentiel à la Clean Architecture",
    "Blocking I/O in async function": "Appel bloquant dans une fonction async",
    "Possible missing await": "`await` potentiellement manquant",
    "Sensitive data potentially logged": "Donnée sensible potentiellement journalisée",
    "Sensitive data printed to stdout": "Donnée sensible écrite sur la sortie standard",
    "Potential SQL injection vulnerability": "Injection SQL potentielle",
    "F-string in SQL statement": "F-string utilisée dans une requête SQL",
    "String format in SQL statement": "Formatage de chaîne dans une requête SQL",
    "Untyped Pydantic field": "Champ Pydantic non typé",
    "Mutable default in Pydantic field": "Valeur mutable par défaut dans un champ Pydantic",
    "Optional field without default": "Champ optionnel sans valeur par défaut",
    "Endpoint missing description": "Description manquante pour une route",
    "Endpoint missing response schema": "Schéma de réponse manquant",
    "No security schemes defined": "Aucun mécanisme de sécurité OpenAPI déclaré",
    "Invalid OpenAPI file": "Fichier OpenAPI invalide",
}


def translate_finding(finding: dict[str, Any]) -> dict[str, Any]:
    """Translate known static diagnostic text while preserving tool output."""
    finding["category"] = CATEGORIES.get(finding.get("category"), finding.get("category"))
    for field in ("title", "detail", "recommendation"):
        value = finding.get(field)
        if isinstance(value, str):
            finding[field] = TEXT.get(value, value)
    return finding
