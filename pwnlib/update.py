"""
# Pwntools Update

In order to ensure that Pwntools users always have the latest and
greatest version, Pwntools automatically checks for updates.

Since this update check takes a moment, it is only performed once
every week.  It can be permanently disabled via:

.. code-block:: bash

    $ echo never > ~/.pwntools-cache/update

"""
import datetime
import json
import os
import time
import xmlrpclib

import packaging.version

from .context import context
from .log import getLogger
from .util.misc import read
from .util.misc import write
from .util.web import wget
from .version import __version__

log = getLogger(__name__)

current_version = packaging.version.Version(__version__)
package_name    = 'pwntools'
package_repo    = 'Gallopsled/pwntools'
update_freq     = datetime.timedelta(days=7).total_seconds()

def available_on_github(prerelease=current_version.is_prerelease):
    """Return True if an update is available on Github.

    >>> available_on_github() # doctest: +ELLIPSIS
    <Version('...')>
    >>> available_on_github(prerelease=False).is_prerelease
    False
    """
    url = 'https://api.github.com/repos/%s/tags' % package_repo

    with context.quiet:
        tags = json.loads(wget(url, timeout = 60))

    # 'pwntools-ancient' is a tag, but not a valid version.
    # Handle this here, and for all potential tags which cause
    # issues.
    versions = []
    for tag in [t['name'] for t in tags]:
        try:
            versions.append(packaging.version.Version(tag))
        except Exception:
            pass

    if not prerelease:
        versions = filter(lambda v: not v.is_prerelease, versions)

    return max(versions)

def available_on_pypi(prerelease=current_version.is_prerelease):
    """Return True if an update is available on PyPI.

    >>> available_on_pypi() # doctest: +ELLIPSIS
    <Version('...')>
    >>> available_on_pypi(prerelease=False).is_prerelease
    False
    """
    client = xmlrpclib.ServerProxy('https://pypi.python.org/pypi')
    versions = client.package_releases('pwntools', True)
    versions = map(packaging.version.Version, versions)

    if not prerelease:
        versions = filter(lambda v: not v.is_prerelease, versions)

    return max(versions)

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

def perform_check(prerelease=current_version.is_prerelease):
    """Perform the update check, and report to the user.

    Arguments:
        prerelease(bool): Whether or not to include pre-release versions.

    Returns:
        A list of arguments to the update command.

    >>> from packaging.version import Version
    >>> pwnlib.update.current_version = Version("999.0.0")
    >>> print perform_check()
    None
    >>> pwnlib.update.current_version = Version("0.0.0")
    >>> perform_check() # doctest: +ELLIPSIS
    ['pip', 'install', '-U', ...]

    >>> def bail(*a): raise Exception()
    >>> github = pwnlib.update.available_on_github
    >>> pypi   = pwnlib.update.available_on_pypi

    >>> pwnlib.update.available_on_github = bail
    >>> perform_check(prerelease=False)
    ['pip', 'install', '-U', 'pwntools']
    >>> perform_check(prerelease=True)  # doctest: +ELLIPSIS
    ['pip', 'install', '-U', 'pwntools...']
    >>> pwnlib.update.available_on_github = github

    >>> pwnlib.update.available_on_pypi = bail
    >>> perform_check(prerelease=False)
    ['pip', 'install', '-U', 'git+https://github.com/Gallopsled/pwntools.git@...']
    >>> perform_check(prerelease=True)  # doctest: +ELLIPSIS
    ['pip', 'install', '-U', 'git+https://github.com/Gallopsled/pwntools.git@...']
    """
    pypi = current_version
    try:
        pypi = available_on_pypi(prerelease)
    except Exception:
        log.warning("An issue occurred while checking PyPI")

    github = current_version
    try:
        github = available_on_github(prerelease)
    except Exception:
        log.warning("An issue occurred while checking Github")

    best = max(pypi, github, current_version)
    where = None
    command = None

    os.utime(cache_file(), None)

    if best == current_version:
        log.info("You have the latest version of Pwntools (%s)" % best)
        return

    command = [
        'pip',
        'install',
        '-U'
    ]

    if best == pypi:
        where = 'pypi'
        pypi_package = package_name
        if best.is_prerelease:
            pypi_package += '==%s' % (best)
        command += [pypi_package]
    else:
        where = 'GitHub'
        command += ['git+https://github.com/%s.git@%s' % (package_repo, github)]

    command_str = ' '.join(command)

    log.info("A newer version of %s is available on %s (%s --> %s).\n" % (package_name, where, current_version, best) +
             "Update with: $ %s" % command_str)

    return command

def check_automatically():
    if should_check():
        message  = ["Checking for new versions of %s" % package_name]
        message += ["To disable this functionality, set the contents of %s to 'never'." % cache_file()]
        log.info("\n".join(message))
        perform_check()
