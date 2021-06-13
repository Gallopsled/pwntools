import re


def align_address(address, align):
    """Align the address to the given size."""
    return address + ((align - (address % align)) % align)


def get_libc_version_from_name(name):
    """Tries to identify the glibc version based on the filename

    Args:
        name: The filename of the libc, which usually is something
            like libc-2.32.so

    Returns:
        tuple(int, int): The glibc version in format (major, minor)

    Examples:
        >>> get_libc_version_from_name("libc-2.23.so")
        (2, 23)

        >>> try:
        ...     get_libc_version_from_name("libc.so")
        ... except ValueError as e:
        ...     print(e)
        Unable to get libc version from filename libc.so

    """
    matches = re.search(r"libc6?[-_](\d+)\.(\d+)\.so", name)

    if matches is None:
        raise ValueError("Unable to get libc version from filename %s" % name)

    libc_version = tuple(int(_) for _ in matches.groups())
    return libc_version


def get_main_arena_addr(libc, pointer_size):
    malloc_hook_addr = libc.symbols["__malloc_hook"]
    return align_address(malloc_hook_addr + pointer_size, 0x20)  # only for x86, for arm is other technique
