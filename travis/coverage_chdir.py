import coverage
import os
import sys

os.environ.setdefault("COVERAGE_PROCESS_START", ".coveragerc")
coverage.process_startup()

__file__ = os.path.abspath(sys.argv.pop(2))
with open(__file__) as fp:
    code = compile(fp.read(), __file__, 'exec')
os.chdir(sys.argv.pop(1))
exec(code, globals())
