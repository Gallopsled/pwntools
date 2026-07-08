---
tool_name: pwntools
mcp_server: pwntools.mcp.server
version: 1.0
author: AI Assistant
created: 2026-07-08
updated: 2026-07-08
tags: [exploit-development, ctfs, rop-chain, binary-exploitation]
---

# pwntools MCP Skill

## 概述

pwntools 是 CTF 和漏洞利用开发的首选框架，提供丰富的二进制分析和利用工具。通过 MCP Server，AI Agent 可以自动化 ELF 分析、ROP 链构建、汇编/反汇编和模式生成。

### 主要功能

- **ELF 分析**: 加载和分析 ELF 二进制文件
- **汇编/反汇编**: 汇编和反汇编指令
- **ROP 链构建**: 自动构建 ROP 链
- **模式生成**: 生成和查找 cyclic 模式
- **打包/解包**: 数据打包和解包
- **字符串提取**: 从 ELF 中提取字符串
- **安全检查**: 检查二进制安全特性

### 适用场景

- CTF Pwn 题求解
- 漏洞利用开发
- ROP 链构建
- Shellcode 开发
- 二进制安全审计

## 工具选择指南

### 何时使用 pwntools

- 需要快速分析 ELF 二进制文件
- 需要构建 ROP 链
- 需要汇编/反汇编指令
- 需要生成 cyclic 模式
- 需要进行二进制漏洞利用开发

### 与其他工具的对比

| 工具 | 类型 | 优势 | 劣势 |
|------|------|------|------|
| pwntools | 利用开发 | ROP 自动化、快速原型 | 主要用于 x86/ARM |
| Ghidra | 静态分析 | 反编译质量高 | 无利用开发功能 |
| pwndbg | 动态调试 | 实时分析 | 需要运行环境 |
| ROPgadget | ROP 分析 | 专注于 gadget 查找 | 无自动构建能力 |

### 典型使用场景

1. **缓冲区溢出利用**: 分析保护机制、构建 ROP 链
2. **格式化字符串漏洞**: 构造读写原语
3. **堆漏洞利用**: 分析堆布局、构造利用
4. **Shellcode 开发**: 汇编和测试 shellcode

## 支持的工具

### 核心工具

- `load_elf` - 加载 ELF 文件
- `get_elf_strings` - 提取字符串
- `assemble` - 汇编代码
- `disassemble` - 反汇编字节
- `find_gadgets` - 查找 ROP gadgets
- `build_rop_chain` - 构建 ROP 链
- `cyclic_pattern` - 生成 cyclic 模式
- `cyclic_find` - 查找偏移
- `pack_value` - 打包数据
- `unpack_value` - 解包数据

## 参数最佳实践

### load_elf

```python
# 推荐：启用安全检查
result = load_elf(
    file_path="/path/to/binary",
    checksec=True  # 检查安全特性
)

# 分析 ELF 结构
result = load_elf(
    file_path="/path/to/binary",
    checksec=True,
    analyze_sections=True,
    analyze_segments=True
)
```

### build_rop_chain

```python
# 推荐：明确指定目标
result = build_rop_chain(
    gadgets=gadgets["gadgets"],
    target_address=0x401200,  # 目标地址
    bad_bytes=[0x0a, 0x00]  # 避免的字节
)

# 构建 execve shell 链
result = build_rop_chain(
    gadgets=gadgets["gadgets"],
    target_type="execve",
    binsh_address=0x402000
)
```

### cyclic_pattern

```python
# 推荐：指定合适的长度
result = cyclic_pattern(length=200)

# 使用自定义字母表
result = cyclic_pattern(
    length=200,
    alphabet="abcdefghijklmnopqrstuvwxyz"
)
```

### assemble

```python
# 推荐：指定架构和操作系统
result = assemble(
    code="nop; nop; ret",
    arch="amd64",
    os="linux"
)

# 汇编 shellcode
result = assemble(
    code="xor rdi, rdi; mov rax, 60; syscall",  # exit(0)
    arch="amd64",
    os="linux"
)
```

## 错误处理

参考 [MCP_ERROR_HANDLING.md](../MCP_ERROR_HANDLING.md) 中的错误码定义。

### 二进制分析错误 (2000-2999)

| 错误码 | 名称 | 解决方案 |
|--------|------|----------|
| 2001 | BINARY_LOAD_FAILED | 检查文件格式是否为 ELF |
| 2002 | INVALID_BINARY_FORMAT | 确认是有效的 ELF 文件 |
| 2003 | ARCHITECTURE_NOT_SUPPORTED | 检查架构是否为 x86/ARM |
| 2006 | ADDRESS_INVALID | 检查地址是否在有效范围内 |
| 2007 | DISASSEMBLY_FAILED | 确认字节是否为有效指令 |

### 常见错误及解决方案

**错误 1: ROP 链构建失败**
```
Error: ROP_CHAIN_FAILED - Cannot build ROP chain
```
解决方案：
- 检查是否有足够的 gadgets
- 放宽 bad_bytes 限制
- 尝试不同的目标地址

**错误 2: 汇编失败**
```
Error: ASSEMBLY_FAILED - Cannot assemble instruction
```
解决方案：
- 检查指令语法是否正确
- 确认架构和操作系统设置
- 使用简单的指令测试

**错误 3: cyclic 查找失败**
```
Error: CYCLIC_NOT_FOUND - Pattern not found
```
解决方案：
- 确认使用了相同的字母表
- 检查模式长度是否足够
- 验证崩溃地址是否正确

## Workflow 示例

### 基础工作流：缓冲区溢出分析

```python
async def analyze_buffer_overflow(binary_path):
    # 1. 加载 ELF 并检查安全特性
    elf = await load_elf(file_path=binary_path, checksec=True)
    print(f"CANARY: {elf['security']['canary']}")
    print(f"NX: {elf['security']['nx']}")
    print(f"PIE: {elf['security']['pie']}")
    
    # 2. 提取字符串
    strings = await get_elf_strings(file_path=binary_path, min_length=4)
    interesting = [s for s in strings["strings"] 
                  if any(kw in s["value"].lower() for kw in ["win", "flag", "shell"])]
    print(f"Found {len(interesting)} interesting strings")
    
    # 3. 生成 cyclic 模式
    pattern = await cyclic_pattern(length=200)
    print(f"Pattern: {pattern['pattern'][:50]}...")
    
    # 4. 查找 ROP gadgets
    gadgets = await find_gadgets(file_path=binary_path)
    pop_rdi = next((g for g in gadgets["gadgets"] if "pop rdi" in g["assembly"]), None)
    if pop_rdi:
        print(f"Found pop rdi; ret: {hex(pop_rdi['address'])}")
```

### 高级工作流：ROP 链构建

```python
async def build_exploit(binary_path, target_address):
    # 1. 加载 ELF
    elf = await load_elf(file_path=binary_path, checksec=True)
    
    # 2. 查找 gadgets
    gadgets = await find_gadgets(file_path=binary_path)
    
    # 3. 构建 ROP 链
    rop_chain = await build_rop_chain(
        gadgets=gadgets["gadgets"],
        target_address=target_address,
        bad_bytes=[0x0a, 0x00]  # 避免换行和空字节
    )
    
    print(f"ROP chain length: {rop_chain['chain_length']}")
    print(f"ROP chain: {rop_chain['chain']}")
    
    # 4. 组装最终 payload
    payload = rop_chain["chain"]
    
    # 5. 打包地址
    packed_addr = await pack_value(value=target_address, word_size=64)
    print(f"Packed address: {packed_addr['packed']}")
    
    return payload
```

### 多工具协作：完整利用开发

```python
async def develop_exploit(binary_path, remote_host, remote_port):
    # 1. 使用 Ghidra 分析二进制
    ghidra_result = await ghidra_client.call_tool("load_binary", {
        "binary_path": binary_path
    })
    
    # 2. 提取关键字符串和函数
    strings = await ghidra_client.call_tool("get_strings", {"min_length": 4})
    functions = await ghidra_client.call_tool("get_functions", {})
    
    # 3. 使用 pwntools 分析 ELF
    elf = await load_elf(file_path=binary_path, checksec=True)
    
    # 4. 查找 gadgets
    gadgets = await find_gadgets(file_path=binary_path)
    
    # 5. 构建 ROP 链
    win_func = next(f for f in functions["functions"] if "win" in f["name"].lower())
    rop_chain = await build_rop_chain(
        gadgets=gadgets["gadgets"],
        target_address=win_func["address"]
    )
    
    # 6. 生成 payload
    pattern = await cyclic_pattern(length=100)
    offset = await cyclic_find(
        pattern=pattern["pattern"],
        value="0x41414141"  # 从崩溃中获取
    )
    
    # 7. 组装最终 payload
    payload = pattern["pattern"][:offset["offset"]]
    payload += rop_chain["chain"]
    
    print(f"Payload length: {len(payload)}")
    print(f"Payload: {payload.hex()}")
    
    # 8. 发送到远程目标
    # 这里需要使用 pwntools 的 remote 功能
    # 但 MCP 工具可能不直接支持，需要结合其他工具
```

## Prompt 模板

### 基础调用模板

```python
# 调用 pwntools MCP 工具
async def analyze_with_pwntools():
    # 加载 ELF
    result = await mcp_client.call_tool(
        tool_name="load_elf",
        arguments={"file_path": "/path/to/binary", "checksec": True}
    )
    
    if result["status"] == "success":
        elf = result["data"]
        print(f"Architecture: {elf['arch']}")
        print(f"Security: {elf['security']}")
    else:
        print(f"Error: {result['error_message']}")
```

### 高级分析模板

```python
# 自动化 ROP 链构建
async def automated_rop_builder(binary_path, target_address):
    """
    自动化 ROP 链构建流程：
    1. 加载 ELF
    2. 查找 gadgets
    3. 构建 ROP 链
    4. 验证链的有效性
    """
    # 加载
    elf = await mcp_client.call_tool("load_elf", {
        "file_path": binary_path,
        "checksec": True
    })
    
    # 查找 gadgets
    gadgets = await mcp_client.call_tool("find_gadgets", {
        "file_path": binary_path
    })
    
    # 构建链
    rop_chain = await mcp_client.call_tool("build_rop_chain", {
        "gadgets": gadgets["data"]["gadgets"],
        "target_address": target_address,
        "bad_bytes": [0x0a, 0x00]
    })
    
    if rop_chain["status"] == "success":
        print(f"Built ROP chain with {rop_chain['data']['chain_length']} gadgets")
        return rop_chain["data"]["chain"]
    else:
        print(f"Failed to build ROP chain: {rop_chain['error_message']}")
        return None
```

### 自动化脚本模板

```python
#!/usr/bin/env python3
"""
pwntools MCP 自动化利用开发脚本
"""
import asyncio
from mcp import Client

async def main():
    async with Client("pwntools") as client:
        # 加载 ELF
        elf = await client.call_tool("load_elf", {
            "file_path": "challenge",
            "checksec": True
        })
        print(f"Architecture: {elf['data']['arch']}")
        print(f"NX: {elf['data']['security']['nx']}")
        print(f"PIE: {elf['data']['security']['pie']}")
        
        # 查找 gadgets
        gadgets = await client.call_tool("find_gadgets", {
            "file_path": "challenge"
        })
        print(f"Found {len(gadgets['data']['gadgets'])} gadgets")
        
        # 生成 cyclic 模式
        pattern = await client.call_tool("cyclic_pattern", {
            "length": 200
        })
        print(f"Pattern: {pattern['data']['pattern'][:50]}...")
        
        # 构建 ROP 链
        rop_chain = await client.call_tool("build_rop_chain", {
            "gadgets": gadgets["data"]["gadgets"],
            "target_address": 0x401200
        })
        
        if rop_chain["status"] == "success":
            print(f"ROP chain: {rop_chain['data']['chain'][:50]}...")

if __name__ == "__main__":
    asyncio.run(main())
```

## 最佳实践

### 性能优化建议

1. **缓存 ELF 分析结果**
   - 避免重复加载相同的 ELF
   - 缓存 gadgets 列表
   - 缓存安全检查结果

2. **优化 ROP 链构建**
   - 使用 `bad_bytes` 过滤无效 gadgets
   - 限制搜索范围
   - 优先使用短链

3. **批量操作**
   - 批量查找 gadgets
   - 批量打包数据
   - 减少 MCP 调用次数

### 安全注意事项

1. **隔离环境**
   - 在虚拟机中测试利用
   - 避免在主机上运行恶意代码
   - 限制网络访问

2. **数据保护**
   - 不要将敏感二进制的利用代码上传
   - 安全存储利用代码
   - 注意法律合规性

3. **结果验证**
   - 在隔离环境中测试利用
   - 验证 ROP 链的正确性
   - 检查 bad bytes 过滤

### 常见问题解答

**Q: 如何处理 PIE 二进制？**
A: 需要信息泄露获取基址，然后计算实际地址，或使用 partial overwrite。

**Q: 如何处理 NX 保护？**
A: 使用 ROP 链绕过 NX，或使用 mprotect 使内存可执行。

**Q: 如何处理 CANARY？**
A: 需要泄露 canary 值，可以使用格式化字符串漏洞或暴力破解（32位）。

**Q: 如何构建 execve shell 的 ROP 链？**
A: 使用 `build_rop_chain` 的 `target_type="execve"` 选项，提供 `/bin/sh` 字符串地址。

**Q: 如何处理 ASLR？**
A: 使用信息泄露获取基址，或使用 partial overwrite 绕过 ASLR。

---

**相关资源**
- [pwntools 项目](https://github.com/Gallopsled/pwntools)
- [MCP 协议](https://modelcontextprotocol.io/)
- [错误处理规范](../MCP_ERROR_HANDLING.md)
