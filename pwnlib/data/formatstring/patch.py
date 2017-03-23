import argparse
import pwnlib

p = argparse.ArgumentParser()
p.add_argument('infile')
p.add_argument('outfile')
p.add_argument('plt_entries', nargs='+')

def main():
    args = p.parse_args()

    i = pwnlib.context.arch = pwnlib.elf.ELF(args.infile)
    trap = pwnlib.asm.asm(pwnlib.shellcraft.trap())

    for plt in args.plt_entries:
        i.write(i.plt[plt], trap)

    i.save(args.outfile)

if __name__ == '__main__':
    main()
