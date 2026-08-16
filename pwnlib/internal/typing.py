from os import PathLike
from typing import Literal, Protocol, TextIO, TypeAlias

StrPath: TypeAlias = str | PathLike[str]
BytesPath: TypeAlias = bytes | PathLike[bytes]
StrOrBytesPath: TypeAlias = str | bytes | PathLike[str] | PathLike[bytes]

BytesLike: TypeAlias = bytes | bytearray | memoryview
ASCIIStr: TypeAlias = str | bytes | bytearray

# for term.text
WhenSetter: TypeAlias = Literal["always", "never", "auto"] | TextIO
class TextDecorator(Protocol):
    def __call__(self, desc: str, when: WhenSetter | None = None) -> str: ...
