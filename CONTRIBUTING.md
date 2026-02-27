# Contributing to RTOSploit

## Development Setup

```bash
git clone https://github.com/rtosploit/rtosploit
cd rtosploit
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## Running Tests

```bash
python -m pytest tests/unit/ -v
```

## Code Style

- Python: follow PEP 8, use type hints
- Rust: use `cargo fmt` and `cargo clippy`

## Adding Exploit Modules

1. Create `rtosploit/exploits/<rtos>/mymodule.py`
2. Extend `ExploitModule` ABC
3. Add tests to `tests/unit/test_<rtos>_exploits.py`
4. Submit PR

## License

By contributing, you agree that your contributions will be licensed under GPL-3.0-only.
