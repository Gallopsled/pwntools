import datetime
import json
import pip
import pkg_resources
import os
import time

from .context import context
from .log import getLogger
from .version import __version__
from .util.misc import read
from .util.misc import write
from .util.web import wget

log = getLogger(__name__)

current_version = pkg_resources.parse_version(__version__)
package_name    = 'pwntools'
package_repo    = 'Gallopsled/pwntools'
update_freq     = datetime.timedelta(days=7).total_seconds()

def available_on_github():
    """Return True if an update is available on Github."""
    url = 'https://api.github.com/repos/%s/tags' % package_repo

    with context.quiet:
        tags = json.loads(wget(url))

    return max(map(pkg_resources.parse_version, [t['name'] for t in tags]))

def available_on_pypi():
    """Return True if an update is available on PyPI."""
    search_command = pip.commands.search.SearchCommand()
    options, _ = search_command.parse_args([package_name])
    pypi_hits = search_command.search(package_name, options)
    for hit in pip.commands.search.transform_hits(pypi_hits):
        if hit['name'] != 'pwntools':
            continue
        return max(map(pkg_resources.parse_version, hit['versions']))

def cache_file():
    """Returns the path of the file used to cache update data, and ensures that it exists."""
    cache_dir  = os.path.expanduser('~/.pwntools-cache')
    cache_file = os.path.join(cache_dir, 'update')

    if not os.path.isdir(cache_dir):
        os.makedirs(cache_dir)

    if not os.path.exists(cache_file):
        write(cache_file, '')

    return cache_file

def last_check():
    """Return the date of the last check"""
    return os.path.getmtime(cache_file())

def should_check():
    """Return True if we should check for an update"""
    if read(cache_file()).strip() == 'never':
        return False
    return time.time() > (last_check() + update_freq)

def perform_check():
    """Perform the update check, and report to the user."""
    pypi = current_version
    try:
        pypi = available_on_pypi()
    except:
        log.warning("An issue occurred while checking PyPI")

    github = current_version
    try:
        github = available_on_github()
    except:
        log.warning("An issue occurred while checking Github")

    best = max(pypi, github, current_version)
    where = None
    command = None

    os.utime(cache_file(), None)

    if best == current_version:
        log.info("You have the latest version of Pwntools (%s)" % best)
        return

    if best == pypi:
        where = 'pypi'
        command = 'pip install -U %s' % package_name
    else:
        where = 'GitHub'
        command = 'pip install -U git+https://github.com/%s.git@%s' % (package_repo, github)

    log.info("A newer version of %s is available on %s (%s --> %s).\n" % (package_name, where, current_version, best) +
             "Update with: $ %s" % command)


def check_automatically():
    if should_check():
        message  = ["Checking for new versions of %s" % package_name]
        message += ["To disable this functionality, set the contents of %s to 'never'." % cache_file()]
        log.info("\n".join(message))
        perform_check()
