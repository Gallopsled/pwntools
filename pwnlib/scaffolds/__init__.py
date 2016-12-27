#!/usr/bin/env python2

class PwnlibTemplate:
    def pre():
        pass

    def post():
        pass

class RemoteExploitTemplate(PwnlibTemplate):
    _template_dir = 'Remote Exploit'
    summary = 'New remote exploit'
