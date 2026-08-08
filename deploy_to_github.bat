@echo off
REM Script de déploiement Windows pour FastAPI Doctor v3.0.0

echo === Déploiement de FastAPI Doctor v3.0.0 ===

REM Vérifier que git est installé
where git >nul 2>nul
if errorlevel 1 (
    echo Erreur: git n'est pas installé
    exit /b 1
)

REM Vérifier le statut git
echo 1. Vérification du statut git...
git status --porcelain >nul
if not errorlevel 1 (
    echo Attention: Il y a des changements non commités
    set /p CONTINUE="Voulez-vous continuer ? (y/n): "
    if /i not "%CONTINUE%"=="y" (
        exit /b 1
    )
)

REM Mettre à jour la version
echo 2. Mise à jour de la version à 3.0.0...
powershell -Command "(Get-Content pyproject.toml) -replace 'version = \"2.1.0\"', 'version = \"3.0.0\"' | Set-Content pyproject.toml"
powershell -Command "(Get-Content setup.py) -replace 'version = \"2.1.0\"', 'version = \"3.0.0\"' | Set-Content setup.py"

REM Créer un tag de version
echo 3. Création du tag v3.0.0...
git add pyproject.toml setup.py CHANGELOG.md README.md
git commit -m "Release v3.0.0: Analyses avancées et architecture modulaire" || echo Commit peut avoir échoué (peut-être aucun changement)
git tag -a v3.0.0 -m "Version 3.0.0 - Analyses avancées et architecture modulaire"

REM Build du package
echo 4. Construction du package Python...
python -m pip install --upgrade build twine
python -m build

REM Tests
echo 5. Exécution des tests...
python -m pytest tests/ -v

REM Vérification du package
echo 6. Vérification du package...
python -m twine check dist/*

echo === Déploiement prêt ===
echo.
echo Pour publier sur PyPI:
echo   python -m twine upload dist/*
echo.
echo Pour pousser sur GitHub:
echo   git push origin main --tags
echo.
echo Pour créer une release GitHub:
echo   1. Allez sur https://github.com/votre-username/fastapi-doctor/releases/new
echo   2. Sélectionnez le tag v3.0.0
echo   3. Titre: FastAPI Doctor v3.0.0
echo   4. Description: Copiez le contenu de CHANGELOG.md
echo   5. Upload des fichiers dist/fastapi_doctor-3.0.0-py3-none-any.whl et dist/fastapi-doctor-3.0.0.tar.gz
echo   6. Publier la release

pause