from pwn import memoize
from os import path

def randomua():
    import random

    @memoize(use_file = False)
    def get_agents():
        return open(
            path.join(
                path.dirname(path.realpath(__file__)),
                'useragents.txt')
            ).read().strip().split('\n')

    return random.sample(get_agents(), 1)[0]
