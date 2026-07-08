# pwntools MCP Server

Model Context Protocol (MCP) Server for pwntools, enabling AI agents to perform exploit development tasks.

## Overview

The pwntools MCP Server provides tools for:

- **ELF Analysis**: Load and analyze ELF binaries, extract symbols, PLT/GOT, and security properties
- **Assembly/Disassembly**: Assemble code and disassemble bytes for multiple architectures
- **ROP Chain Construction**: Find gadgets and build ROP chains
- **Exploit Utilities**: Generate cyclic patterns, pack/unpack values, and more

## Installation

The MCP server is included with pwntools. Install pwntools:

```bash
pip install pwntools
```

## Usage

### Running the Server

Start the MCP server using the command-line interface:

```bash
python -m pwnlib.mcp
```

Or with custom options:

```bash
python -m pwnlib.mcp --transport stdio --log-level INFO
```

### Transport Options

- `stdio` (default): Standard input/output for local integration
- `sse`: Server-Sent Events for web-based clients
- `http`: HTTP transport for remote access

### Configuration Options

```bash
python -m pwnlib.mcp [OPTIONS]

Options:
  --transport [stdio|sse|http]  Transport mechanism (default: stdio)
  --log-level [DEBUG|INFO|WARNING|ERROR]  Logging level (default: WARNING)
  --host HOST                   Host for HTTP/SSE transport (default: localhost)
  --port PORT                   Port for HTTP/SSE transport (default: 8000)
  --path PATH                   Path for HTTP transport (default: /mcp)
```

## Available Tools

### ELF Analysis

#### `load_elf`

Load an ELF binary and extract security properties and symbols.

**Parameters:**
- `file_path` (str): Path to the ELF binary file
- `checksec` (bool): Whether to check security properties (default: True)

**Returns:**
```json
{
  "file_path": "/path/to/binary",
  "arch": "amd64",
  "bits": 64,
  "endianness": "little",
  "entry_point": "0x400000",
  "address": "0x400000",
  "symbols": {"main": "0x401000", ...},
  "symbol_count": 42,
  "plt": {"printf": "0x400500", ...},
  "got": {"printf": "0x601000", ...},
  "security": {
    "canary": true,
    "nx": true,
    "pie": false,
    "relro": "Partial"
  }
}
```

#### `get_elf_strings`

Extract strings from an ELF binary.

**Parameters:**
- `file_path` (str): Path to the ELF binary file
- `min_length` (int): Minimum string length (default: 4)

**Returns:**
```json
{
  "file_path": "/path/to/binary",
  "count": 15,
  "strings": [
    {
      "section": ".rodata",
      "offset": "0x1234",
      "content": "Hello, World!",
      "length": 13
    }
  ]
}
```

### Assembly/Disassembly

#### `assemble`

Assemble code into machine code bytes.

**Parameters:**
- `code` (str): Assembly code (e.g., "mov eax, 0; ret")
- `arch` (str): Target architecture (default: "amd64")
- `os` (str): Target operating system (default: "linux")

**Returns:**
```json
{
  "bytes": "b800000000c3",
  "length": 6,
  "arch": "amd64"
}
```

#### `disassemble`

Disassemble machine code bytes into assembly instructions.

**Parameters:**
- `bytes_hex` (str): Hex string of bytes (e.g., "b800000000c3")
- `arch` (str): Target architecture (default: "amd64")
- `vma` (int): Virtual memory address for display (default: 0)

**Returns:**
```json
{
  "assembly": "   0:\tb8 00 00 00 00           mov    eax,0x0\n   5:\tc3                       ret",
  "instruction_count": 2,
  "arch": "amd64",
  "bytes_length": 6
}
```

### ROP Chain Tools

#### `find_gadgets`

Find ROP gadgets in a binary.

**Parameters:**
- `file_path` (str): Path to the ELF binary file
- `register` (str, optional): Register name to filter gadgets (e.g., "eax", "rdi")
- `max_count` (int): Maximum number of gadgets to return (default: 50)

**Returns:**
```json
{
  "file_path": "/path/to/binary",
  "arch": "amd64",
  "gadget_count": 25,
  "gadgets": [
    {
      "address": "0x401234",
      "instructions": ["pop rdi", "ret"],
      "regs": ["rdi"],
      "move": 16
    }
  ]
}
```

#### `build_rop_chain`

Build a ROP chain for function calls.

**Parameters:**
- `file_path` (str): Path to the ELF binary file
- `calls` (list): List of function calls with 'name'/'address' and 'args'

**Example:**
```json
{
  "calls": [
    {"name": "system", "args": ["/bin/sh"]},
    {"name": "exit", "args": [0]}
  ]
}
```

**Returns:**
```json
{
  "file_path": "/path/to/binary",
  "chain": "4889c748c7c0...",
  "length": 64,
  "dump": "0x0000: 0x401234 pop rdi; ret\n0x0008: 0x402000 \"/bin/sh\"\n...",
  "call_count": 2
}
```

### Utility Tools

#### `cyclic_pattern`

Generate a cyclic pattern for offset detection.

**Parameters:**
- `length` (int): Length of the pattern to generate
- `n` (int): Size of each unique substring (default: 4)

**Returns:**
```json
{
  "pattern": "61616161626161...",
  "pattern_ascii": "aaaabaaacaaadaaa...",
  "length": 100,
  "substring_size": 4
}
```

#### `cyclic_find`

Find the offset of a substring in a cyclic pattern.

**Parameters:**
- `pattern_hex` (str): Hex string of the cyclic pattern
- `sub` (str): Substring to find (hex string or ASCII)
- `n` (int): Size of each unique substring (default: 4)

**Returns:**
```json
{
  "offset": 44,
  "found": true,
  "substring": "61616162"
}
```

#### `pack_value`

Pack an integer value into bytes (little-endian).

**Parameters:**
- `value` (int): Integer value to pack
- `arch` (str): Target architecture (default: "amd64")

**Returns:**
```json
{
  "bytes": "41414141",
  "length": 4,
  "value": "0x41414141",
  "arch": "amd64"
}
```

#### `unpack_value`

Unpack bytes into an integer value (little-endian).

**Parameters:**
- `bytes_hex` (str): Hex string of bytes to unpack
- `arch` (str): Target architecture (default: "amd64")

**Returns:**
```json
{
  "value": 1094795585,
  "value_hex": "0x41414141",
  "bytes_length": 4,
  "arch": "amd64"
}
```

## Integration with AI Agents

The MCP server can be integrated with AI agents that support the Model Context Protocol:

### Claude Desktop

Add to your Claude Desktop configuration:

```json
{
  "mcpServers": {
    "pwntools": {
      "command": "python",
      "args": ["-m", "pwnlib.mcp", "--transport", "stdio"]
    }
  }
}
```

### Custom Clients

Connect to the server using any MCP-compatible client:

```python
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

server_params = StdioServerParameters(
    command="python",
    args=["-m", "pwnlib.mcp"]
)

async with stdio_client(server_params) as (read, write):
    async with ClientSession(read, write) as session:
        await session.initialize()
        
        # Use tools
        result = await session.call_tool(
            "load_elf",
            arguments={"file_path": "/path/to/binary"}
        )
```

## Use Cases

### 1. Automated Exploit Development

AI agents can analyze binaries, identify vulnerabilities, and construct exploits:

```python
# Load binary and check security
elf_info = await session.call_tool("load_elf", {"file_path": "./vulnerable"})

# Find gadgets for ROP chain
gadgets = await session.call_tool("find_gadgets", {"file_path": "./vulnerable"})

# Build exploit
chain = await session.call_tool("build_rop_chain", {
    "file_path": "./vulnerable",
    "calls": [{"name": "system", "args": ["/bin/sh"]}]
})
```

### 2. Binary Analysis

Extract information from binaries for reverse engineering:

```python
# Get all symbols
elf = await session.call_tool("load_elf", {"file_path": "./binary"})

# Extract strings
strings = await session.call_tool("get_elf_strings", {"file_path": "./binary"})

# Disassemble code
asm = await session.call_tool("disassemble", {"bytes_hex": "b800000000c3"})
```

### 3. Exploit Testing

Generate and test exploit payloads:

```python
# Generate cyclic pattern for offset detection
pattern = await session.call_tool("cyclic_pattern", {"length": 200})

# Find offset after crash
offset = await session.call_tool("cyclic_find", {
    "pattern_hex": pattern["pattern"],
    "sub": "61616162"
})

# Pack addresses for exploit
addr = await session.call_tool("pack_value", {"value": 0x401234})
```

## Error Handling

The server provides specific error types:

- `ELFNotFoundError`: ELF file cannot be loaded
- `AssemblyError`: Assembly fails
- `DisassemblyError`: Disassembly fails
- `ROPError`: ROP chain construction fails
- `GadgetNotFoundError`: Required gadget cannot be found

## Architecture Support

The MCP server supports all architectures that pwntools supports:

- x86 (i386)
- x86_64 (amd64)
- ARM
- AArch64
- MIPS
- PowerPC
- And more...

## License

Same as pwntools (MIT License)
