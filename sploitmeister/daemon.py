#-*- encoding: utf-8 -*-

import threading
import Queue
from pwn import log
import sys
import time


class Daemon(object):
    ''' This module acts as a scheduler daemon, responsible for executing exploits read from a particular database

Not sure whether this should be based on threading or subprocesses, or even distribute tasks onto other workers (vms/clouds/whatever).
'''

    def __init__(self, database):
        self.db = database

    def _getNewTask(self):
        return []

    def start(self):
        log.info("Initiating main loop")
        while True:
            newTasks = self._getNewTasks()
            for task in newTasks:
                log.info("executing task %s" % str(task))

            time.sleep(60)







if __name__ == "__main__":
    log.warning("Ich bin ein Scheduler!")
    log.warning("oder nicht :(")
    sys.exit(0)
