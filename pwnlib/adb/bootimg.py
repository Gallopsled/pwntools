from __future__ import division

import ctypes

BOOT_MAGIC = b"ANDROID!"
BOOT_MAGIC_SIZE = 8
BOOT_NAME_SIZE = 16
BOOT_ARGS_SIZE = 512
BOOT_EXTRA_ARGS_SIZE = 1024


class boot_img_hdr(ctypes.Structure):
    _fields_ = [
        ('magic', ctypes.c_char * BOOT_MAGIC_SIZE),

        ('kernel_size', ctypes.c_uint32),
        ('kernel_addr', ctypes.c_uint32),

        ('ramdisk_size', ctypes.c_uint32),
        ('ramdisk_addr', ctypes.c_uint32),

        ('second_size', ctypes.c_uint32),
        ('second_addr', ctypes.c_uint32),

        ('tags_addr', ctypes.c_uint32),
        ('page_size', ctypes.c_uint32),
        ('unused', ctypes.c_uint32),

        ('os_version', ctypes.c_uint32),

        ('name', ctypes.c_char * BOOT_NAME_SIZE),
        ('cmdline', ctypes.c_char * BOOT_ARGS_SIZE),
        ('id', ctypes.c_char * 8),

        ('extra_cmdline', ctypes.c_char * BOOT_EXTRA_ARGS_SIZE),
    ]

class BootImage(object):
    def __init__(self, data):
        self.data = data
        self.header = boot_img_hdr.from_buffer_copy(data)

        PAGE = self.page_size

        # The kernel starts at the beginning of the second page.
        self.kernel = self.data[PAGE:PAGE+self.kernel_size]

    def __getattr__(self, name):
        value = getattr(self.header, name, None)
        if value is not None:
            return value
        return getattr(super(BootImage, self), name)
