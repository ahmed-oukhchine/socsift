"""Allow ``python -m socsift`` to behave like the installed command."""

from socsift.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
