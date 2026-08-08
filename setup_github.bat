@echo off
echo ========================================
echo FastAPI Doctor - GitHub Setup
echo ========================================
echo.

echo Étape 1: Vérification Git...
git --version >nul 2>nul
if errorlevel 1 (
    echo Erreur: Git n'est pas installé
    echo Téléchargez Git depuis: https://git-scm.com/downloads
    pause
    exit /b 1
)

echo Étape 2: Configuration Git...
git config user.name "guerschom1103"
git config user.email "guerschom1103@users.noreply.github.com"

echo.
echo ========================================
echo INSTRUCTIONS POUR GITHUB
echo ========================================
echo.
echo 1. Allez sur: https://github.com/new
echo.
echo 2. Remplissez:
echo    - Repository name: fastapi_doctor_v2.1.0
echo    - Description: Professional audit orchestrator for Python/FastAPI projects
echo    - Public: Oui
echo    - Initialize with README: Non (décocher)
echo    - Add .gitignore: Python
echo    - Choose a license: MIT License
echo.
echo 3. Cliquez sur "Create repository"
echo.
echo 4. Exécutez ces commandes dans le terminal:
echo    git remote add origin https://github.com/guerschom1103/fastapi_doctor_v2.1.0.git
echo    git branch -M main
echo    git push -u origin main
echo.
echo 5. Créez une release:
echo    git tag -a v3.0.0 -m "FastAPI Doctor v3.0.0"
echo    git push origin v3.0.0
echo.
echo ========================================
echo CONFIGURATION DES PERMISSIONS
echo ========================================
echo.
echo Pour configurer les permissions:
echo 1. Allez sur: https://github.com/guerschom1103/fastapi_doctor_v2.1.0/settings
echo 2. Cliquez sur "Manage access"
echo 3. Seul vous (guerschom1103) aurez accès en écriture
echo 4. Les autres pourront seulement lire et créer des issues
echo.
echo ========================================
echo DÉPLOIEMENT PyPI (Optionnel)
echo ========================================
echo.
echo Pour publier sur PyPI:
echo 1. Créez un compte sur: https://pypi.org
echo 2. Installez twine: pip install twine
echo 3. Build le package: python -m build
echo 4. Upload: python -m twine upload dist/*
echo.
pause