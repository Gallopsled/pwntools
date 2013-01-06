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
'''

from pwn import log
import sys
import pymongo

class Sploitmeister(object):
    def __init__(self):
        pass

    def listExploits(self):
        pass

    def insertExploit(self, config):
        pass

    def removeExploit(self, config):
        pass

    def editExploit(self, config):
        pass


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Schrödingers Sploitmeister module :D")
    parser.add_argument('-i', '--insert', action="store", help="Insert new exploit")
    parser.add_argument('-r', '--remove', action="store", help="Remove existing exploit (ID)")
    parser.add_argument('-l', '--list',   action="store", help="List existing exploits")
    parser.add_argument('-e', '--edit',   action="store", help="Edit existing exploit")

    result = parser.parse_args()

    log.warning("Avast ye, here be pirates... or nothing...")
    sys.exit(0)
