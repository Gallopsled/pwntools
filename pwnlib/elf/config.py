"""
Kernel-specific ELF functionality
"""


class KernelConfig(object):
    def __init__(self, name, title, requires=[], excludes=[], minver=0, maxver=99):

        #: Name of the configuration option
        self.name = name

        #: Section to which the configuration point belongs
        self.title = title

        #: List of configuration items, one of which must be present,
        #: for this checker to be used.
        self.requires = set(requires)

        #: List of configuration items, NONE of which must be present,
        #: for this checker to be used.
        self.excludes = set(excludes)

        #: Kernel version that this check should be enforced on
        self.minver = map(int, str(minver).split('.'))
        self.maxver = map(int, str(maxver).split('.'))

    def relevant(self, config):

        # If any of the excluded options are ENABLED,
        # this config is not relevant.
        if self.excludes:
            for value in self.excludes & set(config):
                if config.get(value, False):
                    return False

        # If any of the required options are PRESENT but DISABLED,
        # this config is not relevant.
        if self.requires:
            for value in self.requires & set(config):
                if config.get(value, False):
                    return True

            # We did not find a required value
            return False

        # If we are not in the correct version range, bail
        if 'version' in config:
            version = config['version']

            if not (self.minver <= version < self.maxver):
                return False

        return True

    def check(self, value):
        raise NotImplementedError()

    def __call__(self, config):
        """__call__(config) -> str

        Check whether the configuration point is set correctly.

        Arguments:
            config(dict): Dictionary of all configuration points

        Returns:
            A tuple (result, message) where result is whether the
            option is correctly configured, and message is an optional
            message describing the error.
        """
        if not self.relevant(config):
            return (True, '')
        return self.check(config.get(self.name, None))

class Enabled(KernelConfig):
    def __init__(self, name, **kw):
        super(Enabled, self).__init__(name, 'Not Enabled', **kw)
    def check(self, config):
        return (bool(config), '')

class EnabledIfPresent(Enabled):
    def check(self, config):
        if config is None:
            return (True, '')
        return super(EnabledIfPresent, self).check(config)

class Disabled(KernelConfig):
    def __init__(self, name, **kw):
        super(Disabled, self).__init__(name, 'Not Disabled', **kw)
    def check(self, config):
        return (not bool(config), '')

class Minimum(KernelConfig):
    def __init__(self, name, minimum, **kw):
        super(Minimum, self).__init__(name, 'Misconfigured', **kw)
        self.minimum = minimum
    def check(self, value):
        if value is None or value < self.minimum:
            return (False, "Should be at least {}".format(self.minimum))
        return (True, '')

kernel_configuration = [
# Enabled
    Enabled('STRICT_DEVMEM', requires=['DEVMEM']),
    Enabled('IO_STRICT_DEVMEM', requires=['DEVMEM']),
    Enabled('SYN_COOKIES'),
    Enabled('DEBUG_CREDENTIALS'),
    Enabled('DEBUG_NOTIFIERS'),
    Enabled('DEBUG_LIST'),
    Enabled('SECCOMP'),
    Enabled('SECCOMP_FILTER', minver=3.5, requires=['HAVE_ARCH_SECCOMP_FILTER']),
    Enabled('SECURITY'),
    # Enabled('SECURITY_YAMA'),
    Enabled('HARDENED_USERCOPY', minver=4.8),
    Enabled('SLAB_FREELIST_RANDOM', minver=4.7),
    # Enabled('SLUB_DEBUG'),
    # Enabled('PAGE_POISONING'),
    # Enabled('PAGE_POISONING_NO_SANITY'),
    # Enabled('PAGE_POISONING_ZERO'),
    Enabled('CC_STACKPROTECTOR', excludes=['CC_STACKPROTECTOR_STRONG']),
    Enabled('CC_STACKPROTECTOR_STRONG', minver=3.14),
    Enabled('PANIC_ON_OOPS', minver=3.5),
    Enabled('DEBUG_SET_MODULE_RONX', requires=['MODULES']),
    Enabled('DEBUG_RODATA'),
    Enabled('SECURITY_KPTR_RESTRICT'),
    Enabled('SECURITY_PERF_EVENTS_RESTRICT'),
    Enabled('SECURITY_DMESG_RESTRICT'),
    Enabled('SECURITY_NETWORK'),
    Enabled('SECURITY_SELINUX'),
    Enabled('ARCH_HAS_ELF_RANDOMIZE'),
    EnabledIfPresent('MSM_KERNEL_PROTECT'),

# Not really security relevant, but come on guys
    Enabled('COREDUMP'),

# Disabled
    Disabled('ACPI_CUSTOM_METHOD'),
    Disabled('COMPAT_BRK'),
    Disabled('DEVKMEM'),
    Disabled('DEVMEM'),
    Disabled('COMPAT_VDSO'),
    Disabled('KEXEC'),
    Disabled('BINFMT_MISC'),
    Disabled('LEGACY_PTYS'),
    Disabled('MODULES'),
    Disabled('KEXEC'),
    Disabled('SECURITY_SELINUX_DISABLE'),
    Disabled('MISC_FILESYSTEMS'),
    Disabled('SCSI_TGT'),
    Disabled('SCSI_CONSTANTS'),
    Disabled('SCSI_LOGGING'),
    Disabled('SCSI_SCAN_ASYNC'),
    Disabled('CONFIG_MEDIA_RADIO_SUPPORT'),
    Disabled('CONFIG_PFT'),
    Disabled('CONFIG_SYSVIPC'),


    # Permits reloading the kernel from disk
    Disabled('HIBERNATION'),

    # Prior to v4.1, assists heap memory attacks; best to keep interface disabled
    Disabled('INET_DIAG', maxver=4.1),


# x86-specific
    Enabled('HIGHMEM64G', requires=['X86_32']),
    Enabled('X86_PAE', requires=['X86_32']),
    Disabled('LEGACY_VSYSCALL_NONE', requires=['X86_32', 'X86_64'], minver=4.4),
    Disabled('CONFIG_IA32_EMULATION'),
    Disabled('X86_X32'),
    Disabled('MODIFY_LDT_SYSCALL'),
    Minimum('DEFAULT_MMAP_MIN_ADDR', 65536, requires=['X86_32', 'X86_64']),
    Enabled('RANDOMIZE_BASE', excludes=['ARM']),
    Enabled('RANDOMIZE_MEMORY', requires=['X86_64']),

# ARM specific
    Enabled('VMSPLIT_3G', requires=['ARM']),
    Disabled('STRICT_MEMORY_RWX', requires=['ARM', 'ARM64']),
    Minimum('DEFAULT_MMAP_MIN_ADDR', 32768, requires=['ARM', 'ARM64']),
    Minimum('ARCH_MMAP_RND_BITS', 16, requires=['ARM']),
    Minimum('ARCH_MMAP_RND_BITS', 24, requires=['ARM64']),
    Minimum('ARCH_MMAP_RND_COMPAT_BITS', 16, requires=['ARM64']),
    Enabled('CPU_SW_DOMAIN_PAN', requires=['ARM'], minver=4.3),
    Enabled('CONFIG_ARM64_PAN', requires=['ARM64'], minver=4.3),
    Disabled('OABI_COMPAT'),
    Disabled('CP_ACCESS', requires=['ARM']),
    Disabled('CP_ACCESS64', requires=['ARM64']),

# Only relevant of MODULES are enabled
    Enabled('MODULE_SIG', requires=['MODULES']),
    Enabled('MODULE_SIG_FORCE', requires=['MODULES']),
    Enabled('MODULE_SIG_ALL', requires=['MODULES']),
    Enabled('MODULE_SIG_SHA512', requires=['MODULES']),
    Enabled('MODULE_SIG_KEY', requires=['MODULES']),

]

def parse_kconfig(data):
    """Parses configuration data from a kernel .config.

    Arguments:
        data(str): Configuration contents.

    Returns:
        A :class:`dict`  mapping configuration options.
        "Not set" is converted into ``None``, ``y`` and ``n`` are converted
        into :class:`bool`.  Numbers are converted into :class:`int`.
        All other values are as-is.
        Each key has ``CONFIG_`` stripped from the beginning.

    Examples:

        >>> parse_kconfig('FOO=3')
        {'FOO': 3}
        >>> parse_kconfig('FOO=y')
        {'FOO': True}
        >>> parse_kconfig('FOO=n')
        {'FOO': False}
        >>> parse_kconfig('FOO=bar')
        {'FOO': 'bar'}
        >>> parse_kconfig('# FOO is not set')
        {'FOO': None}
    """
    config = {}

    NOT_SET=' is not set'

    if not data:
        return

    for line in data.splitlines():

        # Not set? Then set to None.
        if NOT_SET in line:
            line = line.split(NOT_SET, 1)[0]
            name = line.strip('# ')
            config[name] = None

        # Set to a value? Extract it
        if '=' in line:
            k, v = line.split('=', 1)

            # Boolean conversions
            if v == 'y':
                v = True
            elif v == 'n':
                v = False
            else:

                # Integer conversions
                try:
                    v = int(v, 0)
                except ValueError:
                    pass

            config[k] = v


    # Strip off all of the CONFIG_ prefixes
    config = ({k.replace('CONFIG_', ''): v for k,v in config.items()})
    return config
