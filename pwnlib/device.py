class Device:
    arch: str | None = None
    bits: int | None = None
    endian: str | None = None
    serial: str | None = None
    os: str | None = None

    def __init__(self, serial: str | None = None):
        self.serial = serial

    def __str__(self) -> str:
        return self.serial or "<no serial>"

    def __eq__(self, other: object) -> bool:
        return self.serial == other or self.serial == str(other)
