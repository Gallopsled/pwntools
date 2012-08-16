import atexit, sys, pwn, os, cPickle

class __Session:
    def __init__(self):
        self.file = os.path.basename(sys.argv[0])
        try:
            self.file += '_' + pwn.HOST
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
        return self.data[key]

    def __setitem__(self, key, data):
        self.data[key] = data

    def __delitem__(self, key):
        del self.data[key]

    def get(self, key, default):
        try:
            return self[key]
        except:
            return default

    def __save__(self):
        fd = open(self.file, 'w')
        cPickle.dump(self.data, fd)
        fd.close()

def session_start():
    s = __Session()
    atexit.register(lambda: s.__save__())
    __builtins__['SESSION'] = s
