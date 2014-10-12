from . import context
import threading

class Thread(threading.Thread):
    def __init__(self, *args, **kwargs):
        super(Thread, self).__init__(*args, **kwargs)
        self.parent_ctx    = context._thread_ctx().__dict__.copy()
        self.__old_bootstrap = self._Thread__bootstrap
        self._Thread__bootstrap = self.__new_bootstrap

    def __new_bootstrap(self):
        context._thread_ctx().__dict__.update(self.parent_ctx)
        return self.__old_bootstrap()