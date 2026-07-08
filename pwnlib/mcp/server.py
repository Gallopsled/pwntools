"""Main MCP server for pwntools exploit development."""

from __future__ import annotations

import logging
from typing import Any

from fastmcp import FastMCP

from .errors import (
    AssemblyError,
    DisassemblyError,
    ELFNotFoundError,
    GadgetNotFoundError,
    ROPError,
)

l = logging.getLogger(__name__)

# Create the FastMCP server instance
mcp = FastMCP("pwntools-mcp", instructions="Exploit development server powered by pwntools")


# ============================================================================
# ELF Analysis Tools
# ============================================================================


@mcp.tool()
def load_elf(
    file_path: str,
    checksec: bool = True,
) -> dict[str, Any]:
    """
    Load an ELF binary and extract security properties and symbols.

    Args:
        file_path: Path to the ELF binary file
        checksec: Whether to check security properties (NX, PIE, Canary, etc.)

    Returns:
        ELF metadata including architecture, entry point, symbols, and security properties
    """
    try:
        from pwnlib.elf import ELF
        from pwnlib.context import context

        elf = ELF(file_path)

        result = {
            "file_path": file_path,
            "arch": elf.arch,
            "bits": elf.bits,
            "endianness": elf.endian,
            "entry_point": hex(elf.entry),
            "address": hex(elf.address),
        }

        # Extract symbols
        symbols = {}
        for name, addr in elf.symbols.items():
            symbols[name] = hex(addr)
        result["symbols"] = symbols
        result["symbol_count"] = len(symbols)

        # Extract PLT/GOT
        plt = {}
        for name, addr in elf.plt.items():
            plt[name] = hex(addr)
        result["plt"] = plt

        got = {}
        for name, addr in elf.got.items():
            got[name] = hex(addr)
        result["got"] = got

        # Security properties
        if checksec:
            result["security"] = {
                "canary": elf.canary,
                "nx": elf.nx,
                "pie": elf.pie,
                "relro": elf.relro,
            }

        return result

    except FileNotFoundError:
        raise ELFNotFoundError(f"File not found: {file_path}")
    except Exception as e:
        raise ELFNotFoundError(f"Failed to load ELF: {e}") from e


@mcp.tool()
def get_elf_strings(
    file_path: str,
    min_length: int = 4,
) -> dict[str, Any]:
    """
    Extract strings from an ELF binary.

    Args:
        file_path: Path to the ELF binary file
        min_length: Minimum string length to include (default: 4)

    Returns:
        Dictionary with 'strings' list containing address and content
    """
    try:
        from pwnlib.elf import ELF

        elf = ELF(file_path)
        strings = []

        # Extract strings from all sections
        for section in elf.sections:
            if hasattr(section, 'data') and section.data():
                data = section.data()
                if isinstance(data, bytes):
                    # Simple string extraction
                    current = b""
                    start_offset = 0
                    for i, byte in enumerate(data):
                        if 32 <= byte <= 126:  # Printable ASCII
                            if not current:
                                start_offset = i
                            current += bytes([byte])
                        else:
                            if len(current) >= min_length:
                                strings.append({
                                    "section": section.name,
                                    "offset": hex(section.header.sh_offset + start_offset),
                                    "content": current.decode('ascii', errors='replace'),
                                    "length": len(current),
                                })
                            current = b""

        return {
            "file_path": file_path,
            "count": len(strings),
            "strings": strings,
        }

    except Exception as e:
        return {"error": str(e), "strings": []}


# ============================================================================
# Assembly/Disassembly Tools
# ============================================================================


@mcp.tool()
def assemble(
    code: str,
    arch: str = "amd64",
    os: str = "linux",
) -> dict[str, Any]:
    """
    Assemble code into machine code bytes.

    Args:
        code: Assembly code to assemble (e.g., "mov eax, 0; ret")
        arch: Target architecture (default: "amd64")
        os: Target operating system (default: "linux")

    Returns:
        Dictionary with 'bytes' (hex string) and 'length'
    """
    try:
        from pwnlib.asm import asm
        from pwnlib.context import context

        with context(arch=arch, os=os):
            result_bytes = asm(code)

        return {
            "bytes": result_bytes.hex(),
            "length": len(result_bytes),
            "arch": arch,
        }

    except Exception as e:
        raise AssemblyError(f"Assembly failed: {e}") from e


@mcp.tool()
def disassemble(
    bytes_hex: str,
    arch: str = "amd64",
    vma: int = 0,
) -> dict[str, Any]:
    """
    Disassemble machine code bytes into assembly instructions.

    Args:
        bytes_hex: Hex string of bytes to disassemble (e.g., "b800000000c3")
        arch: Target architecture (default: "amd64")
        vma: Virtual memory address for display (default: 0)

    Returns:
        Dictionary with 'assembly' (disassembled code) and 'instruction_count'
    """
    try:
        from pwnlib.asm import disasm
        from pwnlib.context import context

        # Convert hex string to bytes
        code_bytes = bytes.fromhex(bytes_hex)

        with context(arch=arch):
            result = disasm(code_bytes, vma=vma)

        # Count instructions (rough estimate by newlines)
        lines = [line for line in result.split('\n') if line.strip()]

        return {
            "assembly": result,
            "instruction_count": len(lines),
            "arch": arch,
            "bytes_length": len(code_bytes),
        }

    except Exception as e:
        raise DisassemblyError(f"Disassembly failed: {e}") from e


# ============================================================================
# ROP Chain Tools
# ============================================================================


@mcp.tool()
def find_gadgets(
    file_path: str,
    register: str | None = None,
    max_count: int = 50,
) -> dict[str, Any]:
    """
    Find ROP gadgets in a binary.

    Args:
        file_path: Path to the ELF binary file
        register: Optional register name to filter gadgets (e.g., "eax", "rdi")
        max_count: Maximum number of gadgets to return (default: 50)

    Returns:
        Dictionary with 'gadgets' list containing address, instructions, and registers
    """
    try:
        from pwnlib.elf import ELF
        from pwnlib.rop import ROP

        elf = ELF(file_path)
        rop = ROP(elf)

        gadgets = []

        if register:
            # Find gadgets for specific register
            try:
                gadget = getattr(rop, register)
                if gadget:
                    gadgets.append({
                        "address": hex(gadget.address),
                        "instructions": gadget.insns,
                        "regs": gadget.regs,
                        "move": gadget.move,
                    })
            except AttributeError:
                pass
        else:
            # Get all gadgets
            for addr, gadget in rop.gadgets.items():
                if len(gadgets) >= max_count:
                    break
                gadgets.append({
                    "address": hex(addr),
                    "instructions": gadget.insns,
                    "regs": gadget.regs,
                    "move": gadget.move,
                })

        return {
            "file_path": file_path,
            "arch": elf.arch,
            "gadget_count": len(gadgets),
            "gadgets": gadgets,
        }

    except Exception as e:
        raise ROPError(f"Failed to find gadgets: {e}") from e


@mcp.tool()
def build_rop_chain(
    file_path: str,
    calls: list[dict[str, Any]],
) -> dict[str, Any]:
    """
    Build a ROP chain for function calls.

    Args:
        file_path: Path to the ELF binary file
        calls: List of function calls, each with 'name' or 'address' and 'args'
               Example: [{"name": "system", "args": ["/bin/sh"]}]

    Returns:
        Dictionary with 'chain' (hex bytes), 'dump' (human-readable), and 'length'
    """
    try:
        from pwnlib.elf import ELF
        from pwnlib.rop import ROP

        elf = ELF(file_path)
        rop = ROP(elf)

        # Build the chain
        for call in calls:
            if "name" in call:
                func_name = call["name"]
                args = call.get("args", [])
                rop.call(func_name, args)
            elif "address" in call:
                func_addr = int(call["address"], 16) if isinstance(call["address"], str) else call["address"]
                args = call.get("args", [])
                rop.call(func_addr, args)

        # Get the chain
        chain_bytes = rop.chain.build()

        return {
            "file_path": file_path,
            "chain": chain_bytes.hex(),
            "length": len(chain_bytes),
            "dump": rop.dump(),
            "call_count": len(calls),
        }

    except Exception as e:
        raise ROPError(f"Failed to build ROP chain: {e}") from e


# ============================================================================
# Utility Tools
# ============================================================================


@mcp.tool()
def cyclic_pattern(
    length: int,
    n: int = 4,
) -> dict[str, Any]:
    """
    Generate a cyclic pattern for offset detection.

    Args:
        length: Length of the pattern to generate
        n: Size of each unique substring (default: 4)

    Returns:
        Dictionary with 'pattern' (bytes as hex) and 'pattern_ascii' (ASCII representation)
    """
    try:
        from pwnlib.util.cyclic import cyclic

        pattern = cyclic(length, n=n)

        return {
            "pattern": pattern.hex(),
            "pattern_ascii": pattern.decode('ascii', errors='replace'),
            "length": len(pattern),
            "substring_size": n,
        }

    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def cyclic_find(
    pattern_hex: str,
    sub: str,
    n: int = 4,
) -> dict[str, Any]:
    """
    Find the offset of a substring in a cyclic pattern.

    Args:
        pattern_hex: Hex string of the cyclic pattern
        sub: Substring to find (hex string or ASCII)
        n: Size of each unique substring (default: 4)

    Returns:
        Dictionary with 'offset' (int) if found
    """
    try:
        from pwnlib.util.cyclic import cyclic_find

        pattern = bytes.fromhex(pattern_hex)

        # Try to interpret sub as hex first, then as ASCII
        try:
            sub_bytes = bytes.fromhex(sub)
        except ValueError:
            sub_bytes = sub.encode('ascii')

        offset = cyclic_find(sub_bytes, n=n)

        return {
            "offset": offset if offset is not None else -1,
            "found": offset is not None,
            "substring": sub,
        }

    except Exception as e:
        return {"error": str(e), "offset": -1}


@mcp.tool()
def pack_value(
    value: int,
    arch: str = "amd64",
) -> dict[str, Any]:
    """
    Pack an integer value into bytes (little-endian by default).

    Args:
        value: Integer value to pack
        arch: Target architecture (default: "amd64")

    Returns:
        Dictionary with 'bytes' (hex string) and 'length'
    """
    try:
        from pwnlib.util.packing import pack
        from pwnlib.context import context

        with context(arch=arch):
            packed = pack(value)

        return {
            "bytes": packed.hex(),
            "length": len(packed),
            "value": hex(value),
            "arch": arch,
        }

    except Exception as e:
        return {"error": str(e)}


@mcp.tool()
def unpack_value(
    bytes_hex: str,
    arch: str = "amd64",
) -> dict[str, Any]:
    """
    Unpack bytes into an integer value (little-endian by default).

    Args:
        bytes_hex: Hex string of bytes to unpack
        arch: Target architecture (default: "amd64")

    Returns:
        Dictionary with 'value' (int) and 'value_hex' (hex string)
    """
    try:
        from pwnlib.util.packing import unpack
        from pwnlib.context import context

        code_bytes = bytes.fromhex(bytes_hex)

        with context(arch=arch):
            value = unpack(code_bytes)

        return {
            "value": value,
            "value_hex": hex(value),
            "bytes_length": len(code_bytes),
            "arch": arch,
        }

    except Exception as e:
        return {"error": str(e)}
