from os import PathLike
from typing import TypeAlias

StrPath: TypeAlias = str | PathLike[str]
BytesPath: TypeAlias = bytes | PathLike[bytes]
StrOrBytesPath: TypeAlias = str | bytes | PathLike[str] | PathLike[bytes]

BytesLike: TypeAlias = bytes | bytearray | memoryview
ASCIIStr: TypeAlias = str | bytes | bytearray
