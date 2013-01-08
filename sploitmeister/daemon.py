#-*- encoding: utf-8 -*-

import threading
import Queue
from pwn import process, log
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
            if not f.endswith('.json'):
                continue
            f_path = os.path.join(self.path, f)
            with open(f_path) as fd:
                try:
                    exploit = json.load(fd)
                    exploit_name = exploit.keys()[0]
                    md5hash = md5.md5(f).hexdigest()

                    if not md5hash in self.exploits.keys():
                        log.info("Found a new exploit")
                        self.exploits.update({md5hash : exploit})
                    else:
                        self.exploits.update({md5hash : exploit})

                except:
                    log.error("Could not read exploit: %s" % f_path)
                    continue

    def _execute(self, exploit):
        if exploit.has_key('active'):
            if exploit['active'].lower() == "false":
                return

        name     = exploit.keys()[0]
        exploits = exploit[name]['exploits']
        targets  = exploit[name]['targets']
        log.info("--------------------------------")
        log.info("Name: %s" % name)
        log.info("Exploits: %s" % str(exploits))
        log.info("Targets: %s" % str(targets))

        for exploit in exploits:
            if not os.path.exists(exploit):
                log.error("Could not find exploit: %s" % exploit)
            else:
                for target in targets:
                    log.info("Executing exploit: %s" % exploit)
                    p = process(exploit, target)
                    res = p.proc.communicate()
                    log.info("result code: %s" % res[0])
        log.info("--------------------------------")


    def start(self, sleeping=60):
        log.info("Initiating main loop")
        self.running = True

        while self.running:
            try:
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                log.info("%s -- Checking for new exploits" % timestamp)
                self._getNewTask()
                for key in self.exploits.keys():
                    exploit = self.exploits[key]
                    self._execute(exploit)

                log.waitfor("%s -- sleeping for %d seconds" % (timestamp, sleeping))
                time.sleep(sleeping)
                log.succeeded()

            except Exception, e:
                log.error("Task execution failed! %s (%s)" % (str(e), str(type(e))))


    def stop(self):
        self.running = False





if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Ich bin ein Scheduler!")
    parser.add_argument('-p', '--path', action="store", required=True, help="Full path to working exploit directory.  Creates dir if it does not exist.")
    parser.add_argument('-s', '--sleeping', action="store", type=int, required=False, default=60, help="seconds of sleeping between checks")

    result = parser.parse_args()
    path = result.path
    sleeping = result.sleeping
    daemon = Daemon(path)
    try:
        daemon.start(sleeping)
    except KeyboardInterrupt:
        log.info("Screw this shit, someone interrupted me!")
        sys.exit()
