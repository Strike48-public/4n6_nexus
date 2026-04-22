"""Make sift_find_evil package executable as a module.

Usage:
    python -m sift_find_evil demo
    python -m sift_find_evil analyze --mft <path> --prefetch <path> --evtx <path>
"""

from .cli import main

if __name__ == "__main__":
    main()
