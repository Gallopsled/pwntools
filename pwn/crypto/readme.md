Cryptanalytic tools
===================

**Please note** that this submodule is a work in progress, and functionality
may change as it is evaluated through use in CTFs. At some point the different
parts may be separated into submodules like `classic`, `mechanical` and
`modern`. That said, the basic API will remain.

This submodule contains tools that help when performing cryptanalysis
of diverse ciphers. Some classic ciphers and helpers for breaking faulty
RSA implementations are currently implemented.

The basic format is as follows:

    _*        : internal functions, but may be of help if you are doing something special
    encrypt_* : encrypt a plaintext using a cipher
    decrypt_* : decrypt a ciphertext using a cipher
    crack_*   : attempt to crack a ciphertext encrypted with a specific cipher

The following is a reference of (some of) the available functions. The goal is to
have complete docstrings for all of them, so if in doubt about usage read them!

Classic ciphers
---------------

The classic ciphers work in Z_26 (A-Z) by default, but a custom alphabet may
also be used by specifying the optional `alphabet` parameter of all methods.

When cracking it is assumed that the plaintext will be English. If this is
not the case one may specify a custom frequency distribution with the
optional `frequencies` parameter.

### Monoalphabetic substitution ciphers

    import pwn.crypto.monoalphabetic as mono

[Generic substitution cipher][0]. The key is a dictionary {'A': 'G', 'B': 'H', ...}`
containing a permutation of the alphabet.

[0]: http://en.wikipedia.org/wiki/Substitution_cipher#Simple_substitution

    encrypt_substitution
    decrypt_substitution
    crack_substitution

[Affine cipher][1] (generalization of the Shift cipher). The key consists
of a tuple (a,b) where a is in Z*_26 and b is in Z_26.

[1]: http://en.wikipedia.org/wiki/Affine_cipher

    _affine_dict
    encrypt_affine
    decrypt_affine
    crack_affine

[Atbash cipher][2] ("mirror" the alphabet). The key is static.

[2]: http://en.wikipedia.org/wiki/Atbash

    _atbash_dict
    encrypt_atbash
    decrypt_atbash
    crack_atbash

[Shift cipher][3] (default to caesar if no key is provided). The key
is an element in Z_26.

[3]: http://en.wikipedia.org/wiki/Caesar_cipher

    _shift_dict
    encrypt_shift
    decrypt_shift
    crack_shift

### Polyalphabetic substitution ciphers

    import pwn.crypto.polyalphabetic as poly

[Vigenere cipher][4]. The key is a string in Z_26 (A-Z).

[4]: http://en.wikipedia.org/wiki/Vigen%C3%A8re_cipher

    crack_vigenere
