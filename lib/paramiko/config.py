# Copyright (C) 2006-2007  Robey Pointer <robeypointer@gmail.com>
#
# This file is part of paramiko.
#
# Paramiko is free software; you can redistribute it and/or modify it under the
# terms of the GNU Lesser General Public License as published by the Free
# Software Foundation; either version 2.1 of the License, or (at your option)
# any later version.
#
# Paramiko is distrubuted in the hope that it will be useful, but WITHOUT ANY
# WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR
# A PARTICULAR PURPOSE.  See the GNU Lesser General Public License for more
# details.
#
# You should have received a copy of the GNU Lesser General Public License
# along with Paramiko; if not, write to the Free Software Foundation, Inc.,
# 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA.

"""
L{SSHConfig}.
"""

import fnmatch
import os
import socket

SSH_PORT=22

class SSHConfig (object):
    """
    Representation of config information as stored in the format used by
    OpenSSH. Queries can be made via L{lookup}. The format is described in
    OpenSSH's C{ssh_config} man page. This class is provided primarily as a
    convenience to posix users (since the OpenSSH format is a de-facto
    standard on posix) but should work fine on Windows too.

    @since: 1.6
    """

    def __init__(self):
        """
        Create a new OpenSSH config object.
        """
        self._config = [ { 'host': '*' } ]

    def parse(self, file_obj):
        """
        Read an OpenSSH config from the given file object.

        @param file_obj: a file-like object to read the config file from
        @type file_obj: file
        """
        configs = [self._config[0]]
        for line in file_obj:
            line = line.rstrip('\n').lstrip()
            if (line == '') or (line[0] == '#'):
                continue
            if '=' in line:
                key, value = line.split('=', 1)
                key = key.strip().lower()
            else:
                # find first whitespace, and split there
                i = 0
                while (i < len(line)) and not line[i].isspace():
                    i += 1
                if i == len(line):
                    raise Exception('Unparsable line: %r' % line)
                key = line[:i].lower()
                value = line[i:].lstrip()

            if key == 'host':
                del configs[:]
                # the value may be multiple hosts, space-delimited
                for host in value.split():
                    # do we have a pre-existing host config to append to?
                    matches = [c for c in self._config if c['host'] == host]
                    if len(matches) > 0:
                        configs.append(matches[0])
                    else:
                        config = { 'host': host }
                        self._config.append(config)
                        configs.append(config)
            else:
                for config in configs:
                    config[key] = value

    def lookup(self, hostname):
        """
        Return a dict of config options for a given hostname.

        The host-matching rules of OpenSSH's C{ssh_config} man page are used,
        which means that all configuration options from matching host
        specifications are merged, with more specific hostmasks taking
        precedence. In other words, if C{"Port"} is set under C{"Host *"}
        and also C{"Host *.example.com"}, and the lookup is for
        C{"ssh.example.com"}, then the port entry for C{"Host *.example.com"}
        will win out.

        The keys in the returned dict are all normalized to lowercase (look for
        C{"port"}, not C{"Port"}. No other processing is done to the keys or
        values.

        @param hostname: the hostname to lookup
        @type hostname: str
        """
        matches = [x for x in self._config if fnmatch.fnmatch(hostname, x['host'])]
        # Move * to the end
        _star = matches.pop(0)
        matches.append(_star)
        ret = {}
        for m in matches:
            for k,v in m.iteritems():
                if not k in ret:
                    ret[k] = v
        ret = self._expand_variables(ret, hostname)
        del ret['host']
        return ret

    def _expand_variables(self, config, hostname ):
        """
        Return a dict of config options with expanded substitutions
        for a given hostname.

        Please refer to man ssh_config(5) for the parameters that
        are replaced.

        @param config: the config for the hostname
        @type hostname: dict
        @param hostname: the hostname that the config belongs to
        @type hostname: str
        """

        if 'hostname' in config:
            config['hostname'] = config['hostname'].replace('%h',hostname)
        else:
            config['hostname'] = hostname

        if 'port' in config:
            port = config['port']
        else:
            port = SSH_PORT

        user = os.getenv('USER')
        if 'user' in config:
            remoteuser = config['user']
        else:
            remoteuser = user

        host = socket.gethostname().split('.')[0]
        fqdn = socket.getfqdn()
        homedir = os.path.expanduser('~')
        replacements = {'controlpath' :
                [
                    ('%h', config['hostname']),
                    ('%l', fqdn),
                    ('%L', host),
                    ('%n', hostname),
                    ('%p', port),
                    ('%r', remoteuser),
                    ('%u', user)
                ],
                'identityfile' :
                [
                    ('~', homedir),
                    ('%d', homedir),
                    ('%h', config['hostname']),
                    ('%l', fqdn),
                    ('%u', user),
                    ('%r', remoteuser)
                ]
                }
        for k in config:
            if k in replacements:
                for find, replace in replacements[k]:
                        config[k] = config[k].replace(find, str(replace))
        return config
