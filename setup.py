from setuptools import setup, find_packages

setup(
    name="credtest",
    version="0.1.0",
    packages=find_packages(),
    package_data={"credtest": ["wordlists/*.txt"]},
    install_requires=[
        "httpx[http2]",
        "beautifulsoup4",
        "lxml",
        "mechanicalsoup",
        "typer[all]",
        "rich",
        "pyyaml",
        "requests",
    ],
    entry_points={
        "console_scripts": [
            "credtest=credtest.cli:app",
        ],
    },
    python_requires=">=3.10",
)
