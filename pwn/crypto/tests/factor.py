from sys import stdout
from pwn.crypto.util import factor, fermat_factor, factor_pollard_rho, TimeoutError

# Fermat numbers to try factoring
F5 = 4294967297
F6 = 18446744073709551617
key = 52663327194823108047941861363554667296911056447871887851271987923908183897674377410438840426978134174085827671405371681087438977062350370399673668797470776186113807376857893834326388369431932515506157599029337496768833168170979530546490477646457979867770363293437566350789835757689162734143512153253903202593
F7 = 340282366920938463463374607431768211457

numbers = [F5, F6, key, F7, F8]
algos = [("Fermat: ", fermat_factor), ("Pollard (Brent): ", factor_pollard_rho), ("General factoring: ", factor)]

for n in numbers:
    print "Factoring {0}".format(n)

    for (desc,alg) in algos:
        stdout.write(desc)
        stdout.flush()
        try: print alg(n)
        except TimeoutError: print "Time limit reached."

    print ""
