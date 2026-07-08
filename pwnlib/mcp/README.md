# pwntools MCP Server

AI Agent 接口，用于通过 Model Context Protocol 访问 pwntools 的 CTF 开发和漏洞利用功能。

## 功能特性

- **ELF 分析**: 加载和分析 ELF 二进制文件
- **汇编/反汇编**: 汇编和反汇编指令
- **ROP 链构建**: 自动构建 ROP 链
- **模式生成**: 生成和查找 cyclic 模式
- **打包/解包**: 数据打包和解包
- **字符串提取**: 从 ELF 中提取字符串
- **安全检查**: 检查二进制安全特性

## 工具列表

### 1. `load_elf`
加载 ELF 文件进行分析。

```python
result = load_elf(file_path="/path/to/binary", checksec=True)
# 返回: {"file_path": "/path/to/binary", "arch": "amd64", "bits": 64, "security": {...}}
```

### 2. `get_elf_strings`
从 ELF 中提取字符串。

```python
result = get_elf_strings(file_path="/path/to/binary", min_length=4)
# 返回: {"strings": [{"value": "Hello", "section": ".rodata", "offset": 0x1000}, ...]}
```

### 3. `assemble`
汇编代码。

```python
result = assemble(code="nop; nop; ret", arch="amd64", os="linux")
# 返回: {"bytes": "9090c3", "length": 3}
```

### 4. `disassemble`
反汇编字节。

```python
result = disassemble(bytes="9090c3", arch="amd64", os="linux")
# 返回: {"assembly": "nop\nnop\nret"}
```

### 5. `find_gadgets`
查找 ROP gadgets。

```python
result = find_gadgets(file_path="/path/to/binary")
# 返回: {"gadgets": [{"address": 0x401000, "instruction": "pop rdi; ret", ...}, ...]}
```

### 6. `build_rop_chain`
构建 ROP 链。

```python
result = build_rop_chain(
    file_path="/path/to/binary",
    target_address=0x401000,
    arguments=[0x1, 0x2, 0x3]
)
# 返回: {"chain": "48 31 c0 5f 5e 5a ...", "gadgets": [...]}
```

### 7. `cyclic_pattern`
生成 cyclic 模式。

```python
result = cyclic_pattern(length=100)
# 返回: {"pattern": "aaaabaaacaaadaaaeaaaf...", "length": 100}
```

### 8. `cyclic_find`
查找 cyclic 模式偏移。

```python
result = cyclic_find(pattern="baaa")
# 返回: {"offset": 4}
```

### 9. `pack_value`
打包数值。

```python
result = pack_value(value=0x41414141, size=4, endian="little")
# 返回: {"packed": "41414141"}
```

### 10. `unpack_value`
解包数值。

```python
result = unpack_value(bytes="41414141", size=4, endian="little")
# 返回: {"value": 0x41414141}
```

## 安装

```bash
pip install pwntools mcp
```

## 使用方法

### 作为独立服务器运行

```bash
python -m pwnlib.mcp.server --stdio
```

### 传输方式

支持三种传输方式：

1. **stdio**（默认）:
   ```bash
   python -m pwnlib.mcp.server --stdio
   ```

2. **SSE**:
   ```bash
   python -m pwnlib.mcp.server --sse --host 127.0.0.1 --port 8000
   ```

3. **HTTP**:
   ```bash
   python -m pwnlib.mcp.server --http --host 127.0.0.1 --port 8000
   ```

## AI Agent 集成示例

### Claude Desktop 配置

```json
{
  "mcpServers": {
    "pwntools": {
      "command": "python",
      "args": ["-m", "pwnlib.mcp.server", "--stdio"]
    }
  }
}
```

### 使用示例

```python
from mcp import Client

async def exploit_development():
    async with Client("pwntools") as client:
        # 加载 ELF
        elf = await client.call_tool("load_elf", {
            "file_path": "/path/to/binary",
            "checksec": True
        })
        print(f"Arch: {elf['arch']}, PIE: {elf['security']['pie']}")
        
        # 生成 cyclic 模式
        pattern = await client.call_tool("cyclic_pattern", {"length": 200})
        print(f"Pattern: {pattern['pattern']}")
        
        # 查找 ROP gadgets
        gadgets = await client.call_tool("find_gadgets", {
            "file_path": "/path/to/binary"
        })
        
        # 构建 ROP 链
        rop = await client.call_tool("build_rop_chain", {
            "file_path": "/path/to/binary",
            "target_address": 0x401000,
            "arguments": [0x1, 0x2, 0x3]
        })
        print(f"ROP chain: {rop['chain']}")
```

## 常见使用场景

### 1. 缓冲区溢出利用

```python
# 1. 加载目标二进制
elf = await client.call_tool("load_elf", {
    "file_path": "vulnerable",
    "checksec": True
})

# 2. 生成 cyclic 模式确定偏移
pattern = await client.call_tool("cyclic_pattern", {"length": 200})

# 3. 找到偏移后构建 ROP 链
rop = await client.call_tool("build_rop_chain", {
    "file_path": "vulnerable",
    "target_address": elf["symbols"]["win"],
    "arguments": []
})

# 4. 打包 payload
payload = await client.call_tool("pack_value", {
    "value": 0x41414141,
    "size": 8,
    "endian": "little"
})
```

### 2. 格式化字符串漏洞

```python
# 1. 加载 ELF
elf = await client.call_tool("load_elf", {"file_path": "fmt_vuln"})

# 2. 提取字符串
strings = await client.call_tool("get_elf_strings", {
    "file_path": "fmt_vuln",
    "min_length": 4
})

# 3. 查找目标地址
for s in strings["strings"]:
    if "flag" in s["value"]:
        print(f"Found: {s['value']} @ {hex(s['offset'])}")
```

### 3. Shellcode 开发

```python
# 1. 编写 shellcode
shellcode = await client.call_tool("assemble", {
    "code": """
    push 0x68
    mov eax, 0x732f6e69
    push eax
    mov edi, esp
    xor eax, eax
    push eax
    push word 0x632d
    mov edi, esp
    """,
    "arch": "amd64",
    "os": "linux"
})

print(f"Shellcode: {shellcode['bytes']}")
print(f"Length: {shellcode['length']}")
```

## 测试

运行测试套件：

```bash
pytest pwntools/tests/test_mcp_tools.py -v
```

测试覆盖率：80%

## 错误处理

所有工具返回统一的错误格式：

```python
{
    "status": "error",
    "message": "Error description"
}
```

## 依赖项

- Python 3.8+
- pwntools
- mcp (Model Context Protocol SDK)

## 许可证

与 pwntools 项目相同。

## 相关链接

- [pwntools 项目](https://github.com/Gallopsled/pwntools)
- [Model Context Protocol](https://modelcontextprotocol.io/)
