from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

with open("requirements.txt", "r", encoding="utf-8") as fh:
    requirements = [line.strip() for line in fh if line.strip() and not line.startswith("#")]

setup(
    name="flamix",
    version="0.1.0",
    author="Flamix Team",
    author_email="security@flamix.io",
    description="Расширяемый менеджер firewall с плагинной архитектурой",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/lavrentijav/Flamix",
    packages=find_packages(),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: System Administrators",
        "Topic :: System :: Networking :: Firewalls",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.8,<=3.13",
    install_requires=requirements,
    entry_points={
        "console_scripts": [
            "flamix=flamix.app:main",
        ],
    },
)

