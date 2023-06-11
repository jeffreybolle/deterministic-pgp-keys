# Deterministic PGP Keys
Generate PGP keys from a 12 word seed phrase.

## Installation

```
cargo install deterministic-pgp-keys
```

## Examples

Example generate a new seed phrase:
```
$ deterministic-pgp-keys --name "Jeffrey Bolle" \
                         --email "jeffreybolle@gmail.com" \
                         --date "2022-09-21" \
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

pub   rsa4096/9976BCC4EF5FB7B1 2022-09-21 [C]
      BCD8DCBB5F14E54C149AEE579976BCC4EF5FB7B1
uid                            Jeffrey Bolle <jeffreybolle@gmail.com>
sub   rsa4096/2A32DF3F36F8107D 2022-09-21 [S]
sub   rsa4096/28DF1DC410534AD4 2022-09-21 [E]
sub   rsa4096/251A4D229D3A2790 2022-09-21 [A]

$ sha256sum public.asc private.asc

4302e29906d2d48a6d7786b38badec2141f7443d5f4020a29ad803c643176b8f  public.asc
a6d0bc672d588a8f6e5697c4269134b7c56c15797d4b024c362a2612ff40ac40  private.asc
```

Recover a key from an existing seed phrase:

```
$ deterministic-pgp-keys --name "Jeffrey Bolle" \
                         --email "jeffreybolle@gmail.com" \
                         --date "2022-09-21" \
                         --public-key public.asc \
                         --private-key private.asc

Seed Phrase: design car dutch struggle hello pluck bubble hospital muffin earn half best

written: private.asc
written: public.asc

$ gpg --keyid-format long --show-key public.asc

pub   rsa4096/9976BCC4EF5FB7B1 2022-09-21 [C]
      BCD8DCBB5F14E54C149AEE579976BCC4EF5FB7B1
uid                            Jeffrey Bolle <jeffreybolle@gmail.com>
sub   rsa4096/2A32DF3F36F8107D 2022-09-21 [S]
sub   rsa4096/28DF1DC410534AD4 2022-09-21 [E]
sub   rsa4096/251A4D229D3A2790 2022-09-21 [A]

$ sha256sum public.asc private.asc

4302e29906d2d48a6d7786b38badec2141f7443d5f4020a29ad803c643176b8f  public.asc
a6d0bc672d588a8f6e5697c4269134b7c56c15797d4b024c362a2612ff40ac40  private.asc
```

## Key Generation Stability

Key generation is only guaranteed to be stable for the same major version number (minor version number for 0.x 
releases).  Please note the version that you used the generate your keys to ensure that you can regenerate them later.
Specifically keys generated on 0.3.x and 0.4.x versions cannot be regenerated on 0.5.x versions.

## Acknowledgements

The majority of the code under the `pgp` module was copied from [pgp](https://github.com/rpgp/rpgp) crate and modified
for the purposes of this project.

## LICENSE
MIT or Apache 2.0
