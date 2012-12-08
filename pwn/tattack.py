import pwn, os

__timeattackbin = os.path.join(pwn.installpath, 'binaries/timeattack')

def simulate(proc, exe, argv, inputfield, inputs):
    proc.send('%s\0' % exe)
    proc.send('%d\0' % len(argv))
    for arg in argv:
        proc.send('%s\0' % arg)
    proc.send('%d\0' % inputfield)
    proc.send('%d\0' % len(inputs))
    for input in inputs:
        proc.send('%s\0' % input)
    data = proc.recvall()
    out = dict()

    i = 0
    while i < len(data):
        j = data.find(' ', i)
        if j == -1: pwn.die('timeattack: parse error')
        idx = int(data[i:j])
        i = j + 1

        j = data.find(' ', i)
        if j == -1: pwn.die('timeattack: parse error')
        count = int(data[i:j])
        i = j + 1

        j = data.find(' ', i)
        if j == -1: pwn.die('timeattack: parse error')
        numb = int(data[i:j])
        i = j + 1

        j = i + numb
        output = data[i:j]
        i = j

        out[inputs[idx]] = (count, output)

    return out

def simulate_local(exe, argv, inputfield, inputs):
    argv = [os.path.basename(exe)] + argv
    return simulate(pwn.process(__timeattackbin), exe, argv, inputfield, inputs)

