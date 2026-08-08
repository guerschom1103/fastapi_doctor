# FastAPI Doctor - Documentation Technique

## Table des Matières
1. [Introduction](#introduction)
2. [Installation](#installation)
3. [Utilisation de Base](#utilisation-de-base)
4. [Analyses Avancées](#analyses-avancées)
5. [Configuration](#configuration)
6. [Intégration CI/CD](#intégration-cicd)
7. [API Référence](#api-référence)
8. [Développement](#développement)
9. [Contributions](#contributions)
10. [Licence](#licence)

## Introduction

FastAPI Doctor est un orchestrateur d'audit professionnel pour projets Python/FastAPI. Il combine des analyses statiques avancées avec l'orchestration d'outils de sécurité et de qualité de code.

### Caractéristiques Principales

- Analyse AST Python avec tracking de flux de données
- Détection avancée d'injection SQL
- Analyse du graphe de dépendances FastAPI
- Validation des schémas OpenAPI
- Analyse de performance async/await
- Orchestration d'outils externes (Ruff, Mypy, Bandit, etc.)
- Rapports multiples (HTML, JSON, SARIF, texte)
- Intégration CI/CD native

## Installation

### Installation depuis PyPI

```bash
# Installation de base
pip install fastapi-doctor

# Installation complète avec toutes les fonctionnalités
pip install "fastapi-doctor[full]"
```

### Installation depuis GitHub

```bash
pip install git+https://github.com/guerschom1103/fastapi_doctor.git
```

### Installation depuis Source

```bash
git clone https://github.com/guerschom1103/fastapi_doctor.git
cd fastapi-doctor
pip install -e .
```

### Dépendances Optionnelles

Pour les analyses avancées, installez les dépendances optionnelles :

```bash
pip install ruff mypy bandit pip-audit semgrep pytest networkx graphviz pyyaml
```

## Utilisation de Base

### Audit Standard

```bash
# Audit d'un projet
fastapi-doctor --path /chemin/vers/projet

# Audit avec sortie JSON
fastapi-doctor --path /chemin/vers/projet --format json --output audit.json

# Audit avec rapport HTML
fastapi-doctor --path /chemin/vers/projet --format html --output rapport.html
```

### Options de Commande

```
--path PATH           Racine du projet à auditer (défaut: .)
--deep                Analyse approfondie avec analyse de flux de données
--tests               Exécuter les tests pytest si disponibles
--no-external         Ne pas exécuter les outils externes
--format {text,json,html,sarif}
                      Format de sortie (défaut: text)
--output OUTPUT       Fichier de sortie
--fail-on {CRITICAL,HIGH,MEDIUM,LOW,INFO}
                      Niveau de sévérité pour échec CI (défaut: HIGH)
--analyze-deps        Analyser le graphe de dépendances FastAPI
--analyze-openapi     Analyser le schéma OpenAPI
--analyze-performance Analyser les performances
--version             Afficher la version
```

## Analyses Avancées

### Analyse de Flux de Données

L'analyse de flux de données tracke les variables sensibles à travers le code :

```bash
fastapi-doctor --path . --deep
```

Détecte :
- Fuites de secrets dans les logs
- Variables sensibles non protégées
- Propagation de données confidentielles

### Analyse SQL Injection

Détection avancée des vulnérabilités SQL :

```bash
fastapi-doctor --path . --deep
```

Détecte :
- Concaténations de strings dans les requêtes SQL
- F-strings et .format() dangereux
- Requêtes N+1
- Utilisation non sécurisée de SQLAlchemy text()

### Analyse des Dépendances FastAPI

Construction et analyse du graphe de dépendances :

```bash
fastapi-doctor --path . --analyze-deps
```

Analyse :
- Cycles de dépendances
- Routes non protégées
- Dépendances manquantes
- Hiérarchie d'injection

### Analyse OpenAPI

Validation des schémas OpenAPI/Swagger :

```bash
fastapi-doctor --path . --analyze-openapi
```

Vérifie :
- Conformité OpenAPI 3.x
- Documentation complète des endpoints
- Schémas de sécurité
- Cohérence routes/documentation

### Analyse de Performance

Détection des problèmes de performance :

```bash
fastapi-doctor --path . --analyze-performance
```

Identifie :
- Patterns N+1
- Boucles coûteuses
- Structures de données volumineuses
- Calculs redondants

## Configuration

### Fichier de Configuration

Créez un fichier `.fastapi-doctor.toml` à la racine de votre projet :

```toml
[analysis]
deep = true
analyze_deps = true
analyze_openapi = true
analyze_performance = true
run_external_tools = true
run_tests = false

[thresholds]
fail_on = "MEDIUM"
max_file_size_mb = 50
max_findings = 1000

[exclusions]
paths = ["tests/", "migrations/", "__pycache__/"]
patterns = ["*_test.py", "test_*.py", "conftest.py"]

[reporting]
format = "html"
output = "audit_report.html"
include_metrics = true
include_dependency_graph = true
include_openapi_analysis = true
include_performance_metrics = true

[security]
check_secrets = true
check_sql_injection = true
check_command_injection = true
check_path_traversal = true
check_authentication = true
check_authorization = true

[performance]
check_n_plus_one = true
check_expensive_loops = true
check_large_data_structures = true
check_redundant_calculations = true

[architecture]
check_clean_architecture = true
check_circular_imports = true
check_god_classes = true
check_tight_coupling = true
check_separation_of_concerns = true
```

### Variables d'Environnement

```
FASTAPI_DOCTOR_CONFIG    Chemin vers le fichier de configuration
FASTAPI_DOCTOR_OUTPUT    Fichier de sortie par défaut
FASTAPI_DOCTOR_FORMAT    Format de sortie par défaut
```

## Intégration CI/CD

### GitHub Actions

```yaml
name: FastAPI Doctor Audit
on: [push, pull_request]
jobs:
  audit:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.10'
      - name: Install FastAPI Doctor
        run: pip install fastapi-doctor[full]
      - name: Run audit
        run: fastapi-doctor --path . --deep --fail-on HIGH --format sarif --output audit.sarif
      - name: Upload SARIF report
        uses: github/codeql-action/upload-sarif@v2
        with:
          sarif_file: audit.sarif
```

### GitLab CI

```yaml
audit:
  image: python:3.10
  script:
    - pip install fastapi-doctor[full]
    - fastapi-doctor --path . --deep --fail-on HIGH
```

### Jenkins

```groovy
pipeline {
    agent any
    stages {
        stage('Audit') {
            steps {
                sh 'pip install fastapi-doctor[full]'
                sh 'fastapi-doctor --path . --deep --fail-on HIGH --format json --output audit.json'
            }
        }
    }
}
```

## API Référence

### Interface de Ligne de Commande

#### Commandes Principales

```bash
# Audit complet
fastapi-doctor audit --path /chemin/projet

# Audit avec configuration personnalisée
fastapi-doctor audit --config custom-config.toml

# Générer un rapport spécifique
fastapi-doctor report --format html --output dashboard.html
```

#### Codes de Sortie

- `0` : Audit réussi (aucun problème au-dessus du seuil)
- `1` : Audit échoué (problèmes au-dessus du seuil)
- `2` : Erreur de configuration
- `3` : Erreur d'exécution

### API Python

```python
from fastapi_doctor import AuditRunner, Config

# Configuration programmatique
config = Config(
    deep=True,
    analyze_deps=True,
    analyze_openapi=True,
    fail_on="HIGH"
)

# Exécution d'audit
runner = AuditRunner(config)
report = runner.audit("/chemin/vers/projet")

# Accès aux résultats
print(f"Score: {report.score}")
print(f"Findings: {len(report.findings)}")

for finding in report.findings:
    if finding.severity in ["CRITICAL", "HIGH"]:
        print(f"{finding.severity}: {finding.title}")
```

## Développement

### Structure du Projet

```
fastapi-doctor/
├── modules/
│   ├── analyzers/          # Analyseurs spécialisés
│   ├── reporters/          # Générateurs de rapports
│   └── utils/              # Utilitaires
├── tests/                  # Tests unitaires
├── fastapi_doctor.py       # Point d'entrée principal
├── pyproject.toml          # Configuration du package
├── setup.py               # Configuration d'installation
└── README.md              # Documentation
```

### Ajouter un Nouvel Analyseur

1. Créez un fichier dans `modules/analyzers/` :

```python
# modules/analyzers/custom_analyzer.py
from typing import Dict, List
from pathlib import Path

class CustomAnalyzer:
    def __init__(self, root: Path, files: List[Path], content_cache: Dict[Path, str]):
        self.root = root
        self.files = files
        self.content_cache = content_cache
    
    def analyze(self) -> Dict:
        findings = []
        metrics = {}
        
        # Logique d'analyse
        # ...
        
        return {
            "findings": findings,
            "metrics": metrics
        }
```

2. Ajoutez l'analyseur dans `fastapi_doctor.py` :

```python
from modules.analyzers.custom_analyzer import CustomAnalyzer

# Dans run_advanced_analyzers()
custom_analyzer = CustomAnalyzer(root, files, content_cache)
custom_results = custom_analyzer.analyze()
findings.extend(custom_results.get("findings", []))
results["custom"] = custom_results.get("metrics", {})
```

### Exécuter les Tests

```bash
# Tous les tests
pytest tests/ -v

# Tests spécifiques
pytest tests/test_fastapi_doctor.py -v

# Avec couverture
pytest tests/ --cov=fastapi_doctor --cov-report=html
```

## Contributions

### Processus de Contribution

1. Fork le repository
2. Créez une branche pour votre fonctionnalité
3. Développez avec des tests
4. Soumettez une Pull Request

### Standards de Code

- Suivre PEP 8
- Ajouter des docstrings
- Écrire des tests unitaires
- Mettre à jour la documentation

### Checklist de Pull Request

- [ ] Tests unitaires ajoutés/mis à jour
- [ ] Documentation mise à jour
- [ ] Code conforme à PEP 8
- [ ] Aucune régression introduite
- [ ] Couverture de code maintenue

## Licence

FastAPI Doctor est distribué sous licence MIT. Voir le fichier `LICENSE` pour plus de détails.

### Copyright

Copyright (c) 2024 guerschom1103. Tous droits réservés.

### Avertissement

FastAPI Doctor est un outil d'audit statique. Il ne remplace pas une revue de code humaine, des tests de pénétration ou une analyse de sécurité approfondie. Les résultats doivent être interprétés par des professionnels de la sécurité.

## Support

### Issues GitHub

Signalez les bugs et demandez des fonctionnalités sur [GitHub Issues](https://github.com/guerschom1103/fastapi_doctor/issues).

### Questions Fréquentes

**Q: FastAPI Doctor modifie-t-il mon code ?**
R: Non, FastAPI Doctor est un outil d'audit non destructif. Il analyse le code sans le modifier.

**Q: Puis-je utiliser FastAPI Doctor sur des projets non-FastAPI ?**
R: Oui, FastAPI Doctor fonctionne sur tout projet Python, mais certaines analyses spécifiques à FastAPI ne seront pas activées.

**Q: Comment ignorer des faux positifs ?**
R: Utilisez la section `[exclusions]` dans le fichier de configuration ou les commentaires dans le code.

**Q: FastAPI Doctor remplace-t-il les linters existants ?**
R: Non, FastAPI Doctor complète les linters existants en ajoutant des analyses spécifiques à FastAPI et en orchestrant les outils externes.

### Ressources Additionnelles

- [Documentation FastAPI](https://fastapi.tiangolo.com/)
- [Python Security Best Practices](https://docs.python.org/3/library/security.html)
- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [GitHub Code Scanning](https://docs.github.com/en/code-security/code-scanning)