# pylint: disable=import-error
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

hiddenimports = [
    "pwnlib.atexception",
    "pwnlib.pep237",
    "pwnlib.update",
    "pwnlib.useragents",
]
hiddenimports += collect_submodules("pwnlib.constants")

datas = collect_data_files("pwnlib.data")
datas += collect_data_files("pwnlib.shellcraft", subdir="templates")
