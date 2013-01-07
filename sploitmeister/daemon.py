#-*- encoding: utf-8 -*-

import threading
import Queue
from pwn import log
import sys
import time
import datetime
import os
import json
import md5

class Daemon(object):
    ''' This module acts as a scheduler daemon, responsible for executing exploits read from a particular database

Not sure whether this should be based on threading or subprocesses, or even distribute tasks onto other workers (vms/clouds/whatever).
'''

    def __init__(self, path):
        log.info("Initiating exploit deployment path: %s" % path)
        if not os.path.isabs(path):
            log.error("Supplied path is not absolute, aborting...")
            raise Exception("Invalid path")

        if not os.path.exists(path):
            os.makedirs(path)

        self.path = path
        self.exploits = {}

    def _getNewTask(self):
        tasks = []
        for f in os.listdir(self.path):
            f_path = os.path.join(self.path, f)
            with open(f_path) as fd:
                try:
                    exploit = json.load(fd)
                    exploit_name = exploit.keys()[0]
                    md5hash = md5.md5(f).hexdigest()

                    if not md5hash in self.exploits.keys():
                        log.info("Loading new exploit: %s" % exploit)
                        self.exploits.update({md5hash : exploit[exploit_name]})
                    else:
                        self.exploits.update({md5hash : exploit[exploit_name]})

                except:
                    log.error("Could not read exploit: %s" % f_path)
                    continue


    def start(self):
        log.info("Initiating main loop")
        self.running = True

        while self.running:
            try:
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                log.info("%s -- Checking for new exploits" % timestamp)
                self._getNewTask()
                for key in self.exploits.keys():
                    exploit = self.exploits[key]
                    if exploit.has_key('active'):
                        if exploit['active'].lower() == "false":
                            continue

                    log.info("executing exploits %s" % str(exploit))

                log.waitfor("%s -- sleeping" % timestamp)
                time.sleep(10)
                log.succeeded()

            except Exception, e:
                log.error("Task execution failed! %s (%s)" % (str(e), str(type(e))))
                

    def stop(self):
        self.running = False





if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Ich bin ein Scheduler!")
    parser.add_argument('-p', '--path', action="store", required=True, help="Full path to working exploit directory.  Creates dir if it does not exist.")

    result = parser.parse_args()
    path = result.path
    daemon = Daemon(path)
    daemon.start()
