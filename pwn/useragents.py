
def randomua():
    import random

    @memoize(use_file = False)
    def get_agents():
        return read('useragents.txt').strip().split('\n')

    return random.sample(get_argents(), 1)[0]
