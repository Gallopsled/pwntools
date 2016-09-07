
class Device(object):
    arch = None
    bits = None
    endian = None
    serial = None
    os = None

    def __init__(self, serial=None):
        self.serial = serial

    def __str__(self):
        return self.serial

    def __eq__(self, other):
        return self.serial == other or self.serial == str(other)
