.. testsetup:: *

   from pprint import pprint
   from pwnlib.util.misc import *
   import os, subprocess

:mod:`pwnlib.util.misc` --- We could not fit it any other place
===============================================================

.. automodule:: pwnlib.util.misc
   :members:

.. doctest::

   >>> import io
   >>> from unittest.mock import MagicMock, patch
   >>> from pwnlib.context import context
   >>> from pwnlib.exception import PwnlibException
   >>> from pwnlib.util import misc
   >>> popen_calls = []
   >>> def fake_popen_factory(run_command_returncode=0, run_command_stdout=b'', run_command_stderr=b''):
   ...     def fake_popen(argv, **kwargs):
   ...         popen_calls.append(argv)
   ...         p = MagicMock()
   ...         p.__enter__.return_value = p
   ...         p.returncode = 0
   ...         if len(argv) == 2:
   ...             p.communicate.return_value = (b'/konsole/MainWindow_1\n', b'')
   ...         elif 'winId' in argv[-1]:
   ...             p.communicate.return_value = (b'1234\n', b'')
   ...         elif 'sessionList' in argv[-1]:
   ...             p.communicate.return_value = (b'1 2\n', b'')
   ...         elif 'runCommand' in argv[-2]:
   ...             assert kwargs['stdout'] == misc.subprocess.PIPE
   ...             assert kwargs['stderr'] == misc.subprocess.PIPE
   ...             p.returncode = run_command_returncode
   ...             p.communicate.return_value = (run_command_stdout, run_command_stderr)
   ...         elif 'processId' in argv[-1]:
   ...             p.communicate.return_value = (b'4321\n', b'')
   ...         else:
   ...             raise AssertionError(f'Unexpected qdbus call: {argv}')
   ...         return p
   ...     return fake_popen
   >>> env = {
   ...     'KONSOLE_VERSION': '240801',
   ...     'KONSOLE_DBUS_SERVICE': 'org.kde.konsole-1234',
   ...     'KONSOLE_DBUS_WINDOW': '/Windows/1',
   ...     'WINDOWID': '1234',
   ... }
   >>> def run_konsole(fake_popen):
   ...     popen_calls.clear()
   ...     with patch.dict(misc.os.environ, env, clear=True):
   ...         with patch.object(misc, 'which', side_effect=lambda n: '/usr/bin/qdbus' if n == 'qdbus' else None):
   ...             with patch.object(misc.subprocess, 'Popen', side_effect=fake_popen):
   ...                 with patch.object(misc.subprocess, 'run'):
   ...                     with context.local(log_console=io.StringIO()):
   ...                         return misc.run_in_new_terminal('echo hello', kill_at_exit=False)
   >>> access_denied = (
   ...     b'Error: org.freedesktop.DBus.Error.AccessDenied\n'
   ...     b'Security sensitive DBus API is disabled in the settings.\n'
   ... )
   >>> try:
   ...     run_konsole(fake_popen_factory(2, run_command_stdout=access_denied))
   ... except PwnlibException as exc:
   ...     error_message = str(exc)
   ... else:
   ...     raise AssertionError('Expected PwnlibException')
   >>> assert 'Enable the security sensitive parts of the DBus API' in error_message, error_message
   >>> assert 'other processes to control Konsole sessions' in error_message, error_message
   >>> assert 'tmux' in error_message, error_message
   >>> assert not any('processId' in arg for call in popen_calls for arg in call)
   >>> try:
   ...     run_konsole(fake_popen_factory(2, run_command_stderr=access_denied))
   ... except PwnlibException as exc:
   ...     error_message = str(exc)
   ... else:
   ...     raise AssertionError('Expected PwnlibException')
   >>> assert 'Enable the security sensitive parts of the DBus API' in error_message, error_message
   >>> assert not any('processId' in arg for call in popen_calls for arg in call)
   >>> pid = run_konsole(fake_popen_factory())
   >>> assert pid == 4321, pid
   >>> assert any('processId' in arg for call in popen_calls for arg in call)
   >>> try:
   ...     run_konsole(fake_popen_factory(
   ...         3,
   ...         run_command_stdout=b'org.example.Unrelated: launch failed',
   ...         run_command_stderr=b'additional diagnostic detail',
   ...     ))
   ... except PwnlibException as exc:
   ...     error_message = str(exc)
   ... else:
   ...     raise AssertionError('Expected PwnlibException')
   >>> assert 'exit code 3' in error_message, error_message
   >>> assert 'stdout:' in error_message, error_message
   >>> assert 'org.example.Unrelated: launch failed' in error_message, error_message
   >>> assert 'stderr: additional diagnostic detail' in error_message, error_message
   >>> assert 'Enable the security sensitive parts of the DBus API' not in error_message, error_message
   >>> assert not any('processId' in arg for call in popen_calls for arg in call)
