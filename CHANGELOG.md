# Changelog

## [3.0.0] - 2024-01-01

### Nouvelles fonctionnalités majeures

#### 1. Analyse de flux de données (Data Flow Analysis)
- **Tracking des variables sensibles** : Détection des fuites de mots de passe, tokens et secrets
- **Analyse de propagation** : Suivi des données sensibles à travers le code
- **Détection des fuites** : Identification des logs, prints et retours contenant des données sensibles

#### 2. Analyse SQL Injection avancée
- **Détection AST** : Analyse syntaxique des requêtes SQL
- **Patterns avancés** : Détection des f-strings, .format() et concaténations dangereuses
- **SQLAlchemy spécifique** : Analyse des appels text() et execute()
- **Requêtes N+1** : Détection des patterns de performance dans les boucles

#### 3. Analyse des dépendances FastAPI
- **Graphe de dépendances** : Construction automatique du graphe
- **Détection de cycles** : Identification des dépendances circulaires
- **Analyse de sécurité** : Vérification des routes non protégées
- **Hiérarchie des dépendances** : Analyse de la structure d'injection

#### 4. Analyse OpenAPI/Swagger
- **Validation des schémas** : Vérification de la conformité OpenAPI 3.x
- **Documentation complète** : Analyse des endpoints, paramètres et réponses
- **Sécurité API** : Vérification des schémas d'authentification
- **Cohérence** : Comparaison routes vs documentation

#### 5. Analyse Pydantic avancée
- **Validation des modèles** : Vérification des validateurs et contraintes
- **Typage fort** : Détection des champs non typés
- **Sécurité des données** : Analyse des champs sensibles
- **Bonnes pratiques** : Vérification des valeurs par défaut mutables

#### 6. Analyse asynchrone
- **Performance async** : Détection des appels bloquants
- **Correction await** : Vérification des await manquants
- **Context managers** : Analyse des async with
- **Deadlocks potentiels** : Détection des patterns problématiques

#### 7. Analyse de performance
- **Optimisations** : Détection des N+1, boucles coûteuses
- **Structures de données** : Analyse des listes/dictionnaires volumineux
- **Calculs redondants** : Identification des opérations répétées
- **Algorithmes** : Détection des implémentations inefficaces

#### 8. Analyse d'architecture
- **Clean Architecture** : Vérification des violations
- **Imports circulaires** : Détection des dépendances cycliques
- **God classes** : Identification des classes trop complexes
- **Couplage** : Analyse de la séparation des préoccupations

### Améliorations techniques

#### Architecture
- **Refactorisation modulaire** : Séparation en modules spécialisés
- **Extensibilité** : Architecture conçue pour les extensions futures
- **Maintenabilité** : Code mieux organisé et documenté

#### Performance
- **Optimisations** : Analyse plus rapide grâce au cache mémoire
- **Parallélisation** : Exécution concurrente des outils externes
- **Parcours unique** : Arborescence parcourue une seule fois

#### Rapports
- **Formats multiples** : HTML, JSON, SARIF, texte
- **Métriques enrichies** : Données détaillées sur chaque analyse
- **Visualisation** : Rapports HTML améliorés avec couleurs et styles

#### Configuration
- **Fichier TOML** : Configuration centralisée
- **Options avancées** : Contrôle granulaire des analyses
- **Exclusions** : Configuration flexible des chemins exclus

#### Intégration
- **CI/CD** : Support amélioré pour GitHub Actions, GitLab CI
- **SARIF** : Intégration native avec GitHub Code Scanning
- **Outils externes** : Orchestration améliorée de ruff, mypy, bandit, etc.

### Corrections de bugs
- **Détection .env** : Correction de la détection des fichiers .env et variantes
- **Performance** : Optimisation du parcours d'arborescence
- **Faux positifs** : Réduction des alertes incorrectes
- **Robustesse** : Meilleure gestion des erreurs et exceptions

### Changements breaking
- **API interne** : Refactorisation complète de l'architecture
- **Configuration** : Nouveau format de fichier de configuration
- **Dépendances** : Nouvelles dépendances optionnelles pour les analyses avancées

### Migration depuis v2.1
1. **Mettre à jour la configuration** : Utiliser le nouveau format `.fastapi-doctor.toml`
2. **Installer les dépendances optionnelles** : `pip install "fastapi-doctor[full]"`
3. **Adapter les scripts CI/CD** : Nouveaux flags `--analyze-deps`, `--analyze-openapi`, etc.
4. **Réviser les exclusions** : Vérifier les chemins exclus dans la nouvelle configuration

## [2.1.0] - 2023-12-01

### Corrections
- **Fichiers .env** : Correction de la détection des fichiers .env et variantes
- **Performance** : Parcours unique de l'arborescence au lieu de 6
- **Lecture unique** : Fichiers Python lus une seule fois au lieu de 5
- **Parallélisation** : Outils externes exécutés en parallèle
- **Détection fonctions** : Correction du calcul de longueur des fonctions

### Améliorations
- **Optimisation** : Durée réduite de 1,47s à 0,08s pour l'analyse de base
- **Robustesse** : Meilleure gestion des erreurs
- **Documentation** : README amélioré avec exemples détaillés

## [2.0.0] - 2023-11-01

### Fonctionnalités
- **Analyse AST** : Analyse syntaxique Python avancée
- **Détection FastAPI** : Routes, dépendances, authentification
- **Sécurité** : Secrets, eval, shell=True, SQL injection
- **Outils externes** : Ruff, mypy, bandit, pip-audit, semgrep
- **Rapports** : HTML, JSON, SARIF, texte
- **CI/CD** : Codes de sortie configurables

### Architecture
- **Code propre** : Séparation des responsabilités
- **Typage** : Annotations de types complètes
- **Documentation** : Docstrings et commentaires
- **Tests** : Suite de tests unitaires