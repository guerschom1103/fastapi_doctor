from setuptools import setup, find_packages

setup(
    name="fastapi-doctor",
    version="3.0.0",
    description="Professional generic audit orchestrator for Python/FastAPI projects",
    long_description=open("README.md", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="FastAPI Doctor Team",
    python_requires=">=3.10",
    packages=find_packages(),
    install_requires=[
        "typing-extensions>=4.0.0",
    ],
    extras_require={
        "full": [
            "ruff>=0.1.0",
            "mypy>=1.0.0",
            "bandit>=1.7.0",
            "pip-audit>=2.0.0",
            "semgrep>=1.0.0",
            "pytest>=7.0.0",
            "networkx>=3.0",
            "graphviz>=0.20.0",
            "pyyaml>=6.0",
        ],
    },
    entry_points={
        "console_scripts": [
            "fastapi-doctor=fastapi_doctor:main",
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: Software Development :: Testing",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
)