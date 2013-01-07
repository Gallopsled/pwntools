#-*- encoding: utf-8 -*-
'''
This module serves as frontend to the sploitmeister scheduling daemon.
Useful for manipulating exploits during a ctf.

Supported operations:
- start new daemon with new exploit database (init when ctf starts)
- insert new exploit, specify targets, location of exploit, and desired delay between executions, e.g. execute every 60 seconds.
- halt exploit for all or specific targets.
- insert new target for existing exploit.
- more stuff?


Idea:
an exploit is a json like this:
exploit1.json:
exploit1 = {
  name = 'Leet hacksploit',
  author = 'Mr. McLeetson',
  exploits = ['/path/to/exploit1.py'],
  targets = ['123.123.123.0', '123.123.123.1'],
  delay = 60,
}

editing an exploit: include ID.
new options for editing:
addTargets
addExploit
removeTarget
removeExploit

e.g.:
edit_exploit2.json = {
  id = 1,
  addExploit = ['/path/to/exploit2.py'],
  removeTarget = ['123.123.123.1']
}



maybe...?



'''

from pwn import log
import sys
import pymongo

class Sploitmeister(object):
    def __init__(self, db):
        self.db = db

    def listExploits(self):
        log.info("listing my current exploits")

    def insertExploit(self, config):
        ''' @return exploit ID
'''
        log.info("inserting exploit with config:\n %s" % str(config))

    def removeExploit(self, ID):
        log.info("removing exploit with id: %s" % str(ID))

    def editExploit(self, config):
        log.info("editing exploit with config:\n %s" % str(config))


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Schrödingers Sploitmeister module :D")
    parser.add_argument('-d', '--db',     action="store", help="The active database name", required=True)
    parser.add_argument('-i', '--insert', action="store", help="Insert new exploit")
    parser.add_argument('-r', '--remove', action="store", help="Remove existing exploit (ID)")
    parser.add_argument('-l', '--list',   action="store_true", help="List existing exploits")
    parser.add_argument('-e', '--edit',   action="store", help="Edit existing exploit")

    result = parser.parse_args()


    sploiter = Sploitmeister(result.db)
    if result.insert:
        sploiter.insertExploit(result.insert)

    if result.remove:
        sploiter.removeExploit(result.remove)

    if result.list:
        sploiter.listExploits()

    if result.edit:
        sploiter.editExploit(result.edit)

    log.warning("Avast ye, here be pirates... or nothing...")
    sys.exit(0)
