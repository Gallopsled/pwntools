"""Entry point for running the pwntools MCP server."""

from __future__ import annotations

import argparse
import logging
import sys

from .server import mcp


def main(argv: list[str] | None = None) -> None:
    """Entry point for running the pwntools MCP server."""
    parser = argparse.ArgumentParser(description="pwntools MCP Server - Exploit development via Model Context Protocol")
    parser.add_argument(
        "--transport",
        choices=["stdio", "sse", "http"],
        default="stdio",
        help="Transport mechanism (default: stdio)",
    )
    parser.add_argument(
        "--log-level",
        choices=["DEBUG", "INFO", "WARNING", "ERROR"],
        default="WARNING",
        help="Logging level (default: WARNING)",
    )
    parser.add_argument(
        "--host",
        default="localhost",
        help="Host for HTTP/SSE transport (default: localhost)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port for HTTP/SSE transport (default: 8000)",
    )
    parser.add_argument(
        "--path",
        default="/mcp",
        help="Path for HTTP transport (default: /mcp)",
    )

    args = parser.parse_args(argv)

    if args.transport == "http" and not args.path.startswith("/"):
        parser.error("--path must start with '/'")

    # Configure logging
    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        stream=sys.stderr,
    )

    # Suppress verbose pwntools logging unless DEBUG
    if args.log_level != "DEBUG":
        logging.getLogger("pwnlib").setLevel(logging.ERROR)

    if args.transport == "stdio":
        mcp.run(transport="stdio")
    elif args.transport == "sse":
        mcp.run(transport="sse", host=args.host, port=args.port)
    elif args.transport == "http":
        mcp.run(transport="http", host=args.host, port=args.port, path=args.path)


if __name__ == "__main__":
    main()
