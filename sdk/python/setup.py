from setuptools import setup, find_packages
from pathlib import Path

readme = (Path(__file__).parent / "README.md").read_text(encoding="utf-8")

setup(
    name="guardian-sdk",
    version="0.2.0",
    description="Guardian SDK for Python",
    long_description=readme,
    long_description_content_type="text/markdown",
    url="https://github.com/your-org/guardian",
    author="Guardian",
    license="MIT",
    packages=find_packages(include=["guardian_sdk", "guardian_sdk.*"]),
    install_requires=[
        "httpx>=0.27.0,<0.28.0",
        "structlog>=23.1.0,<24.0.0",
        "tenacity>=8.2.0,<9.0.0",
        "typing-extensions>=4.0.0",
    ],
    python_requires=">=3.8",
)