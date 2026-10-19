# web-security-lab

A deliberately vulnerable Flask application for **local, authorized practice**,
paired with hardened versions of the same endpoints so the difference is visible
in code and in tests.

> **Warning:** this application contains intentional vulnerabilities (SQL
> injection, reflected XSS, IDOR). Run it only on `127.0.0.1`. Never deploy it to
> a server, never point it at real users or data.

## Endpoints

| Vulnerable | Hardened | Weakness demonstrated |
|---|---|---|
| `POST /vuln/login` | `POST /safe/login` | SQL injection in a login query |
| `GET /vuln/search` | `GET /safe/search` | Reflected XSS |
| `GET /vuln/profile/<id>` | `GET /safe/profile/<id>` | Insecure direct object reference |

## Features

- Small, readable code: each vulnerable line is annotated and its fix is shown.
- Automated tests assert both the vulnerable behavior **and** that the hardened
  endpoints resist the same payloads.
- SQLite in memory of the lab, hashed demo passwords, no external services.

## Installation

```bash
git clone https://github.com/victor-harden/web-security-lab.git
cd web-security-lab
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

## Usage

```bash
python app.py            # serves http://127.0.0.1:5000
```

Demo accounts: `alice` / `alice-password` (admin) and `bob` / `bob-password` (user).

Examples:

```bash
curl -s -X POST localhost:5000/vuln/login -d "username=' OR 1=1 --" -d "password=x"
curl -s "localhost:5000/vuln/search?q=<script>alert(1)</script>"
curl -s "localhost:5000/safe/search?q=<script>alert(1)</script>"
```

## Tests

```bash
python -m unittest discover -s tests -v
```

The suite documents the vulnerability first, then proves the hardened endpoint
rejects it. This is the point of the lab: one behavior, two implementations.

## License

MIT — see [LICENSE](LICENSE). Use only for education and authorized testing.
