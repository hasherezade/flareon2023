# Coppersmith Stereotyped Message Recovery
## Using Sage Math

Copyright 2021-2022 Maxim Masiutin

This file may be distributed on conditions of the
GNU General Public License v3.0

It implements the following function: `message_recover`
to decrypt a `secret` from the message `m` consisting of `prefix | secret | suffix`
if we only know `prefix` and `suffix` but not the `secret`.

Inputs: `prefix`, `sec_len` (length of the secret in bytes), `suffix`, `c`, `n`, `e`

Where `n` and `e` are parts of RSA public key, and `c` is the ciphertext

Output: `m` (message)

Types: `prefix`, `suffix` and `m` are of bytearray type, whereas `sec_len`, `c`, `n` and `e` are integers.


To install the prerequisites, run
`sage -pip install pycryptodome pycrypto`


Original source:
```
https://github.com/maximmasiutin/rsa-coppersmith-stereotyped-message/
```
