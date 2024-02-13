
# ./pwnlib/data/includes/darwin/aarch64.h
# ./pwnlib/constants/darwin/aarch64.py

# https://github.com/nullgemm/instant_macos_sdk (old sdk here, please use real macos device)
# /Library/Developer/CommandLineTools/SDKs/MacOSX14.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/sys/

from pathlib import Path
import re
import sys

# In the future, you should change the version of `MacOSX14.sdk`
sdk_path = Path('/Library/Developer/CommandLineTools/SDKs/MacOSX14.sdk/System/Library/Frameworks/Kernel.framework/Versions/A/Headers/sys/')
if not sdk_path.exists():
    print('missing MacOSX sdk')
    exit(1)

project_path = Path(sys.argv[1])

regex = re.compile(r'^#define\s+([a-zA-Z0-9_-]+)\s+([0-9]+|0x[0-9a-fA-F]+)(?:\s|$)', re.DOTALL)

out_data = {}
for file in sdk_path.iterdir():
    if not file.is_file():
        continue

    print(file.name)
    for line in file.read_text(errors='ignore').split('\n'):
        matched = regex.search(line)
        if not matched:
            continue

        key, value = matched.groups()
        if value.startswith('0') and not value.startswith('0x') and len(value) > 1:
            value = '0o'+value

        print(key, value)
        out_data[key] = value


outbuf1_aarch64 = ''
outbuf1_aarch64 += "from pwnlib.constants.constant import Constant\n"

outbuf1_amd64 = ''
outbuf1_amd64 += "from pwnlib.constants.constant import Constant\n"

outbuf2_aarch64 = ''
outbuf2_amd64 = ''

# https://www.idryman.org/blog/2014/12/02/writing-64-bit-assembly-on-mac-os-x/
# on amd64 syscall offsets from 0x2000000 + syscall number

for key, value in out_data.items():
    value_octal = value
    if value_octal.startswith('0o'):
        value_octal = value_octal.replace('0o', '0')

    outbuf1_aarch64 += "{} = Constant('{}',{})\n".format(key, key, value)
    outbuf2_aarch64 += "#define {} {}\n".format(key, value_octal)

    if key.startswith('SYS_'):
        value = f'{value} + 0x2000000'
        value_octal = f'{value_octal} + 0x2000000'

    outbuf1_amd64 += "{} = Constant('{}',{})\n".format(key, key, value)
    outbuf2_amd64 += "#define {} {}\n".format(key, value_octal)

pp = project_path
(pp / Path('./pwnlib/constants/darwin/aarch64.py')).write_bytes(outbuf1_aarch64.encode())
(pp / Path('./pwnlib/data/includes/darwin/aarch64.h')).write_bytes(outbuf2_aarch64.encode())

(pp / Path('./pwnlib/constants/darwin/amd64.py')).write_bytes(outbuf1_amd64.encode())
(pp / Path('./pwnlib/data/includes/darwin/amd64.h')).write_bytes(outbuf2_amd64.encode())
