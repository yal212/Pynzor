from enum import IntEnum
import typer
from cli.commands import app

BANNER = r"""
██████╗ ██╗   ██╗███╗   ██╗███████╗ ██████╗ ██████╗ 
██╔══██╗╚██╗ ██╔╝████╗  ██║╚══███╔╝██╔═══██╗██╔══██╗
██████╔╝ ╚████╔╝ ██╔██╗ ██║  ███╔╝ ██║   ██║██████╔╝
██╔═══╝   ╚██╔╝  ██║╚██╗██║ ███╔╝  ██║   ██║██╔══██╗
██║        ██║   ██║ ╚████║███████╗╚██████╔╝██║  ██║
╚═╝        ╚═╝   ╚═╝  ╚═══╝╚══════╝ ╚═════╝ ╚═╝  ╚═╝
"""

def main():
    """Print the banner and launch the Typer CLI application."""
    print(BANNER)
    print("Pynzor CLI v.10\n")
    app()

if __name__ == "__main__":
    main()
