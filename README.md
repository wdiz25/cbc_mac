# Assignment 4: Forging Basic CBC-MAC
### Author: William Disman

**Programming Language:** Python 3.14.7, managed with uv

**AES Library:** pycryptodome 4.2.0

**Test Dependencies:** pytest 9.1.1

## How to Run

### Option A: uv (recommended)
uv installs the correct Python version and all dependencies automatically.
```
uv sync
uv run pytest        # run the tests
uv run cbc-mac       # run the 3b/3c demo
```

### Option B: pip
Requires Python 3.14+ (check with `python3 --version`).
```
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -e . pytest
pytest               # run the tests
cbc-mac              # run the 3b/3c demo
```