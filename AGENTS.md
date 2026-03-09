# AGENTS.md

## Cursor Cloud specific instructions

### Project overview

This is a VPN refactoring baseline repo (`opentoplist`). The backend is a pure **Python stdlib** WSGI application — no external pip packages or `requirements.txt`. The only runtime dependency is **Python 3.10+** (3.12 is available in the environment).

### Running commands

The system `python` alias may not exist; use `PYTHON=python3 make <target>` or invoke `python3` directly.

| Task | Command |
|------|---------|
| Unit tests | `PYTHON=python3 make test` |
| Start API server (port 8080) | `PYTHON=python3 make run` |
| Load test (server must be running) | `PYTHON=python3 make loadtest` |

### Key caveats

- The Makefile default `PYTHON ?= python` assumes `python` is on PATH; in this environment it is not — always pass `PYTHON=python3`.
- The API server uses `wsgiref.simple_server` (single-threaded, blocking). Start it in a background shell when you need to curl against it.
- All data is in-memory (`InMemoryStore`); restarting the server resets state. A demo user (`demo` / `demo1234`) and 3 VPN nodes (`sg-1`, `jp-1`, `us-1`) are bootstrapped on startup.
- Gateway scripts (`gateway/scripts/`) require root, WireGuard, and nftables — they are infra scripts for production nodes and are **not runnable** in this dev environment.
- The Kotlin client (`client/android/`) is a design example with no build config.
- No linter is configured in the repo; standard `python3 -m py_compile` can verify syntax.
