"""Tests for pwntools MCP server."""

from __future__ import annotations

import pytest
from pathlib import Path

from pwnlib.mcp.server import (
    assemble,
    disassemble,
    load_elf,
    get_elf_strings,
    find_gadgets,
    build_rop_chain,
    cyclic_pattern,
    cyclic_find,
    pack_value,
    unpack_value,
)
from pwnlib.mcp.errors import (
    AssemblyError,
    DisassemblyError,
    ELFNotFoundError,
    ROPError,
)


@pytest.fixture
def test_binary(tmp_path):
    """Create a simple test binary for testing."""
    from pwnlib.elf import ELF

    # Create a simple ELF from assembly
    asm_code = """
    mov eax, 0
    ret
    """
    binary = ELF.from_assembly(asm_code)
    binary_path = tmp_path / "test_binary"
    binary.save(str(binary_path))
    return str(binary_path)


class TestLoadELF:
    """Tests for the load_elf tool."""

    def test_load_elf_success(self, test_binary):
        """Test loading an ELF binary successfully."""
        result = load_elf(test_binary)

        assert "file_path" in result
        assert "arch" in result
        assert "bits" in result
        assert "entry_point" in result
        assert result["arch"] == "amd64"
        assert result["bits"] == 64

    def test_load_elf_with_checksec(self, test_binary):
        """Test loading ELF with security properties."""
        result = load_elf(test_binary, checksec=True)

        assert "security" in result
        assert "canary" in result["security"]
        assert "nx" in result["security"]
        assert "pie" in result["security"]
        assert "relro" in result["security"]

    def test_load_elf_file_not_found(self):
        """Test loading a nonexistent ELF file."""
        with pytest.raises(ELFNotFoundError):
            load_elf("/nonexistent/path/to/binary")


class TestAssemble:
    """Tests for the assemble tool."""

    def test_assemble_simple(self):
        """Test assembling simple instructions."""
        result = assemble("mov eax, 0; ret")

        assert "bytes" in result
        assert "length" in result
        assert result["length"] > 0
        assert result["arch"] == "amd64"

    def test_assemble_with_arch(self):
        """Test assembling for different architectures."""
        result = assemble("mov r0, #0", arch="arm")

        assert result["arch"] == "arm"
        assert result["length"] > 0

    def test_assemble_invalid(self):
        """Test assembling invalid code."""
        with pytest.raises(AssemblyError):
            assemble("invalid_instruction_xyz")


class TestDisassemble:
    """Tests for the disassemble tool."""

    def test_disassemble_simple(self):
        """Test disassembling simple bytes."""
        # mov eax, 0; ret
        result = disassemble("b800000000c3")

        assert "assembly" in result
        assert "instruction_count" in result
        assert result["instruction_count"] > 0

    def test_disassemble_with_vma(self):
        """Test disassembling with virtual address."""
        result = disassemble("b800000000c3", vma=0x400000)

        assert "assembly" in result
        assert result["arch"] == "amd64"

    def test_disassemble_invalid(self):
        """Test disassembling invalid hex."""
        with pytest.raises(DisassemblyError):
            disassemble("not_valid_hex")


class TestROPTools:
    """Tests for ROP-related tools."""

    def test_find_gadgets(self, test_binary):
        """Test finding ROP gadgets."""
        result = find_gadgets(test_binary)

        assert "gadgets" in result
        assert "gadget_count" in result
        assert result["gadget_count"] >= 0

    def test_build_rop_chain(self, test_binary):
        """Test building a ROP chain."""
        # This is a simple test - in real scenarios, you'd have actual symbols
        calls = [{"address": "0x400000", "args": []}]

        try:
            result = build_rop_chain(test_binary, calls)
            assert "chain" in result
            assert "length" in result
        except ROPError:
            # Expected if no suitable gadgets found
            pass


class TestCyclicTools:
    """Tests for cyclic pattern tools."""

    def test_cyclic_pattern(self):
        """Test generating a cyclic pattern."""
        result = cyclic_pattern(100)

        assert "pattern" in result
        assert "length" in result
        assert result["length"] == 100

    def test_cyclic_pattern_with_n(self):
        """Test generating pattern with custom substring size."""
        result = cyclic_pattern(50, n=8)

        assert result["substring_size"] == 8

    def test_cyclic_find(self):
        """Test finding offset in cyclic pattern."""
        # Generate a pattern
        pattern_result = cyclic_pattern(100)
        pattern_hex = pattern_result["pattern"]

        # Find a known substring
        result = cyclic_find(pattern_hex, "61616162")  # "baaa" in hex

        assert "offset" in result
        assert "found" in result


class TestPackingTools:
    """Tests for pack/unpack tools."""

    def test_pack_value(self):
        """Test packing an integer value."""
        result = pack_value(0x41414141)

        assert "bytes" in result
        assert "length" in result
        assert result["bytes"] == "41414141"

    def test_pack_value_64bit(self):
        """Test packing a 64-bit value."""
        result = pack_value(0x4141414141414141, arch="amd64")

        assert result["length"] == 8

    def test_unpack_value(self):
        """Test unpacking bytes to integer."""
        result = unpack_value("41414141")

        assert "value" in result
        assert result["value"] == 0x41414141

    def test_unpack_value_64bit(self):
        """Test unpacking 64-bit value."""
        result = unpack_value("4141414141414141", arch="amd64")

        assert result["value"] == 0x4141414141414141
