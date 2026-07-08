"""Custom exceptions for pwntools MCP server."""

from __future__ import annotations


class MCPPwnError(Exception):
    """Base exception for MCP pwntools server errors."""


class ELFNotFoundError(MCPPwnError):
    """Raised when an ELF file cannot be loaded."""


class AssemblyError(MCPPwnError):
    """Raised when assembly fails."""


class DisassemblyError(MCPPwnError):
    """Raised when disassembly fails."""


class ROPError(MCPPwnError):
    """Raised when ROP chain construction fails."""


class GadgetNotFoundError(ROPError):
    """Raised when a required gadget cannot be found."""
