import atexit, sys, pwn, os, cPickle

class __Session:
    '''Session handling.
    Used as a dictionary.  One session per program per RHOST.'''
    def __init__(self):
        self.data = None

    def __load__(self):
        if self.data is not None:
            return
        self.file = os.path.basename(sys.argv[0])
        try:
            self.file += '_' + pwn.RHOST
        except:
            pass
        self.file += '.session'
        self.file = os.path.join(sys.path[0], self.file)

        if os.path.exists(self.file):
            fd = open(self.file)
            self.data = cPickle.load(fd)
            fd.close()
        else:
            self.data = dict()

    def __getitem__(self, key):
        self.__load__()
        return self.data[key]

    def __setitem__(self, key, data):
        self.__load__()
        self.data[key] = data

    def __delitem__(self, key):
        self.__load__()
        del self.data[key]

    def get(self, key, default):
        self.__load__()
        try:
            return self[key]
        except:
            return default

    def __save__(self):
        if self.data is not None:
            fd = open(self.file, 'w')
            cPickle.dump(self.data, fd)
            fd.close()

pwn.SESSION = __Session()
atexit.register(lambda: pwn.SESSION.__save__())
