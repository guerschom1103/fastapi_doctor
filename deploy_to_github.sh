#!/bin/bash
# Script de déploiement pour FastAPI Doctor v3.0.0 sur GitHub

set -e  # Arrêter en cas d'erreur

echo "=== Déploiement de FastAPI Doctor v3.0.0 ==="

# Vérifier que git est installé
if ! command -v git &> /dev/null; then
    echo "Erreur: git n'est pas installé"
    exit 1
fi

# Vérifier le statut git
echo "1. Vérification du statut git..."
if [ -n "$(git status --porcelain)" ]; then
    echo "Attention: Il y a des changements non commités"
    read -p "Voulez-vous continuer ? (y/n): " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 1
    fi
fi

# Mettre à jour la version
echo "2. Mise à jour de la version à 3.0.0..."
sed -i 's/version = "2.1.0"/version = "3.0.0"/' pyproject.toml
sed -i 's/version = "2.1.0"/version = "3.0.0"/' setup.py

# Créer un tag de version
echo "3. Création du tag v3.0.0..."
git add pyproject.toml setup.py CHANGELOG.md README.md
git commit -m "Release v3.0.0: Analyses avancées et architecture modulaire" || true
git tag -a v3.0.0 -m "Version 3.0.0 - Analyses avancées et architecture modulaire"

# Build du package
echo "4. Construction du package Python..."
python -m pip install --upgrade build twine
python -m build

# Tests
echo "5. Exécution des tests..."
python -m pytest tests/ -v

# Vérification du package
echo "6. Vérification du package..."
python -m twine check dist/*

echo "=== Déploiement prêt ==="
echo ""
echo "Pour publier sur PyPI:"
echo "  python -m twine upload dist/*"
echo ""
echo "Pour pousser sur GitHub:"
echo "  git push origin main --tags"
echo ""
echo "Pour créer une release GitHub:"
echo "  1. Allez sur https://github.com/votre-username/fastapi-doctor/releases/new"
echo "  2. Sélectionnez le tag v3.0.0"
echo "  3. Titre: FastAPI Doctor v3.0.0"
echo "  4. Description: Copiez le contenu de CHANGELOG.md"
echo "  5. Upload des fichiers dist/fastapi_doctor-3.0.0-py3-none-any.whl et dist/fastapi-doctor-3.0.0.tar.gz"
echo "  6. Publier la release"