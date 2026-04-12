# QRecon — Quantum Cloud Security Reconnaissance Framework

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/release/python-3110/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)

QRecon is the first offensive security reconnaissance framework designed specifically for quantum cloud platforms. It treats IBM Quantum, Amazon Braket, Azure Quantum, and IonQ Cloud as attack surfaces — enumerating their REST API surfaces, probing their authentication and authorization implementations, analyzing submitted quantum circuits for information disclosure, and generating adversarial hypotheses using an AI reasoning layer.

The project is modeled structurally on how classical offensive security tools work (Nmap for discovery, Burp Suite for auth testing, MITRE ATT&CK for taxonomy) but applied to an entirely new target class: quantum cloud infrastructure.

## Table of Contents

- [Q-ATT&CK Matrix](#q-attck-matrix)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Module Reference](#module-reference)
- [Architecture](#architecture)
- [Responsible Use](#responsible-use)
- [Contributing](#contributing)
- [License](#license)

## Q-ATT&CK Matrix

This project includes the first iteration of the Q-ATT&CK matrix, a structured adversarial taxonomy for quantum clouds.
See the [Full Q-ATT&CK Matrix](docs/q-attck-matrix.md).

## Installation

```bash
git clone https://github.com/f2025408135-cyber/QRecon.git
cd QRecon
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

Copy `.env.example` to `.env` and fill in your target platform credentials:

```bash
cp .env.example .env
```

## Quick Start

```bash
# 1. Enumerate IBM Quantum backends
python cli.py enum --platform ibm --output ibm_recon.json

# 2. Run Auth Probes
python cli.py auth --platform ibm --output auth_probes.json

# 3. Analyze a QASM circuit for disclosure risks
python cli.py circuit analyze --file tests/fixtures/sample_circuits/benign_bell.qasm

# 4. View Q-ATT&CK Techniques
python cli.py attck list-techniques --platform ibm
```

## Module Reference

- **`platform_enum`**: Authenticates and gathers topography data (backend inventory, calibration data, APIs).
- **`auth_probe`**: Classical authorization testing adapted to quantum contexts (scope probes, cross-tenant isolation).
- **`circuit_lens`**: Static analysis of OpenQASM circuits for timing oracles and state disclosure.
- **`qhypo`**: AI reasoning agent to generate adversarial hypotheses based on findings.
- **`q_attck`**: The taxonomy definitions and mapping logic.

## Architecture

```text
User -> CLI -> Orchestration Pipeline
                   |-> Platform Enum
                   |-> Auth Probe
                   |-> Circuit Lens
                   \-> QHypo Agent -> Hypothesis JSON
```

## Responsible Use

**This tool is strictly for authorized security research and responsible disclosure purposes.** All credential scanning tools contained within follow responsible disclosure principles. Any discovered credentials, vulnerabilities, or misconfigurations should be reported immediately to the affected platform's security team and should never be used.

## Contributing

Contributions are highly welcome. Please review the open issues and submit pull requests. Ensure all tests pass (`pytest`) and code aligns with Black and Ruff standards before submitting a PR.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
