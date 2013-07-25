def randomua():
    """Return a random useragent string."""
    import random, pwn, os

    @pwn.memoize(use_file = False)
    def get_agents():
        return pwn.read(
                os.path.join(pwn.installpath, 'pwn', 'useragents.txt')
            ).strip().split('\n')

    return random.sample(get_agents(), 1)[0]
