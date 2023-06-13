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

pub   rsa4096/507815B996600F36 2022-09-21 [C]
      AE39CF95A4039CAEFD1C22A7507815B996600F36
uid                            Jeffrey Bolle <jeffreybolle@gmail.com>
sub   rsa4096/D92839349498B4E1 2022-09-21 [S]
sub   rsa4096/F29826BF06FF3C1C 2022-09-21 [E]
sub   rsa4096/A8A8BD8D480C88FB 2022-09-21 [A]

$ sha256sum public.asc private.asc

074722130decd18b9a1eaf1219d5bb358745c517a8af9c3d6a81ead03e25ad50  public.asc
37cf6cc556e27c35a1e9325587079d651e5ca5fd77851676b4929560460c6626  private.asc
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

pub   rsa4096/507815B996600F36 2022-09-21 [C]
      AE39CF95A4039CAEFD1C22A7507815B996600F36
uid                            Jeffrey Bolle <jeffreybolle@gmail.com>
sub   rsa4096/D92839349498B4E1 2022-09-21 [S]
sub   rsa4096/F29826BF06FF3C1C 2022-09-21 [E]
sub   rsa4096/A8A8BD8D480C88FB 2022-09-21 [A]

$ sha256sum public.asc private.asc

074722130decd18b9a1eaf1219d5bb358745c517a8af9c3d6a81ead03e25ad50  public.asc
37cf6cc556e27c35a1e9325587079d651e5ca5fd77851676b4929560460c6626  private.asc
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
