# Deterministic PGP Keys
Generate PGP keys from a 12 word seed phrase

## Examples

Example generate a new seed phrase:
```bash
$ ./deterministic-pgp-keys --name 'Jeffrey Bolle' \
                           --email 'jeffreybolle@gmail.com' \
                           --date '2022-09-21' \
                           --public-key public.asc \
                           --private-key private.asc \
                           --generate

Seed Phrase:

   1: design     7: bubble
   2: car        8: hospital
   3: dutch      9: muffin
   4: struggle  10: earn
   5: hello     11: half
   6: pluck     12: best

written: private.asc
written: public.asc

$ gpg --keyid-format long --show-key public.asc

pub   rsa4096/3C0477EBC839A4EB 2022-09-21 [C]
      40D5580A0D4C2E966A57CA643C0477EBC839A4EB
uid                            Jeffrey Bolle <jeffreybolle@gmail.com>
sub   rsa4096/1ADED7E832E44A9C 2022-09-21 [S]
sub   rsa4096/65C64F42070EDC53 2022-09-21 [E]
sub   rsa4096/17CB25180FCA8973 2022-09-21 [A]

$ sha256sum public.asc private.asc

8074ddb524121edc31a1c6ce616ba37ac71412999802be804f252b33259fa0bc  public.asc
64c44c971ae50ddd3a30c516e5249e736e883b1d7aec018e041b1e0b63a45962  private.asc
```

Recover a key from an existing seed phrase:

```bash
$ ./deterministic-pgp-keys --name 'Jeffrey Bolle' \
                           --email 'jeffreybolle@gmail.com' \
                           --date '2022-09-21' \
                           --public-key public.asc \
                           --private-key private.asc

Seed Phrase: design car dutch struggle hello pluck bubble hospital muffin earn half best

written: private.asc
written: public.asc

$ gpg --keyid-format long --show-key public.asc

pub   rsa4096/3C0477EBC839A4EB 2022-09-21 [C]
      40D5580A0D4C2E966A57CA643C0477EBC839A4EB
uid                            Jeffrey Bolle <jeffreybolle@gmail.com>
sub   rsa4096/1ADED7E832E44A9C 2022-09-21 [S]
sub   rsa4096/65C64F42070EDC53 2022-09-21 [E]
sub   rsa4096/17CB25180FCA8973 2022-09-21 [A]

$ sha256sum public.asc private.asc

8074ddb524121edc31a1c6ce616ba37ac71412999802be804f252b33259fa0bc  public.asc
64c44c971ae50ddd3a30c516e5249e736e883b1d7aec018e041b1e0b63a45962  private.asc
```

## Acknowledgements

The majority of the code under the `pgp` module was copied from [pgp](https://github.com/rpgp/rpgp) crate and modified
for the purposes of this project.

## LICENSE
MIT or Apache 2.0