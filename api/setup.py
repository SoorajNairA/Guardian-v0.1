"""
Setup script for the Guardian API package.
"""
from setuptools import setup, find_packages

setup(
    name="guardian-api",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        "fastapi",
        "google-generativeai",
        "pydantic",
        "httpx",
        "redis",
        "structlog",
    ],
    extras_require={
        "test": [
            "pytest",
            "pytest-asyncio",
            "pytest-cov",
            "httpx",
            "pytest-mock",
        ],
    },
)