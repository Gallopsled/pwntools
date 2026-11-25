"""
Access to the files that are shipped with ``pwnlib``.
"""
import importlib.resources
import os
import shutil
import tempfile

from pwnlib import atexit


def get(path: str):
    r"""get(path) -> importlib.resources.abc.Traversable

    Get a file or directory that is shipped with ``pwnlib``.

    This does not need a file on disk, so it also works if ``pwnlib`` is
    imported from a zip archive.  Use :func:`get_path` if an external
    program needs the file.

    Arguments:
        path(str): Path inside of the ``pwnlib`` package, with ``/`` as separator.

    Example:

        >>> get('data/includes/linux/amd64.h').read_text().splitlines()[0]
        '#define __NR_read 0'
        >>> get('data/includes').is_dir()
        True
        >>> get('data/nope').is_file()
        False
    """
    res = importlib.resources.files('pwnlib')
    for part in path.split('/'):
        res = res / part
    return res


def _extract(res, target):
    if res.is_dir():
        os.mkdir(target)
        for child in res.iterdir():
            _extract(child, os.path.join(target, child.name))
    else:
        with open(target, 'wb') as fd:
            fd.write(res.read_bytes())

_extracted: dict[str, str] = {}

def get_path(path: str) -> str:
    r"""get_path(path) -> str

    Get the path on disk of a file or directory that is shipped with ``pwnlib``.

    If ``pwnlib`` is not on disk (e.g. in a zip archive), the resource is
    extracted to a temporary directory, which is removed on exit.

    Arguments:
        path(str): Path inside of the ``pwnlib`` package, with ``/`` as separator.

    Example:

        >>> os.path.isfile(get_path('gdb_api_bridge.py'))
        True
        >>> os.path.isfile(os.path.join(get_path('data/includes'), 'linux', 'amd64.h'))
        True

        The same from a zip archive:

        >>> import pwnlib, shutil, sys
        >>> tmp = tempfile.mkdtemp()
        >>> _ = shutil.copytree(os.path.dirname(pwnlib.__file__), os.path.join(tmp, 'src', 'pwnlib'))
        >>> archive = shutil.make_archive(os.path.join(tmp, 'pwnlib'), 'zip', os.path.join(tmp, 'src'))
        >>> code = '''if 1:
        ...     from pwnlib import asm, shellcraft, useragents
        ...     from pwnlib.context import context
        ...     from pwnlib.util import crc, resources
        ...     context.clear(arch='amd64', os='linux')
        ...     print('SYS_execve' in shellcraft.sh())
        ...     print('amd64.linux.sh' in shellcraft.templates)
        ...     print(asm.cpp('SYS_execve').strip())
        ...     print(len(useragents.getall()) > 22000)
        ...     print(hex(crc.crc_32_iso_hdlc(b'123456789')))
        ...     print(resources.get_path('gdb_api_bridge.py').endswith('gdb_api_bridge.py'))
        ... '''
        >>> env = dict(os.environ, PYTHONPATH=archive, PWNLIB_NOTERM='1')
        >>> print(subprocess.check_output([sys.executable, '-c', code], cwd=tmp, env=env, text=True))
        True
        True
        59
        True
        0xcbf43926
        True
        <BLANKLINE>
    """
    res = get(path)
    if isinstance(res, os.PathLike):
        return os.fspath(res)

    if path not in _extracted:
        tmp = tempfile.mkdtemp(prefix='pwnlib-resource-')
        atexit.register(shutil.rmtree, tmp, ignore_errors=True)
        target = os.path.join(tmp, res.name)
        _extract(res, target)
        _extracted[path] = target
    return _extracted[path]
