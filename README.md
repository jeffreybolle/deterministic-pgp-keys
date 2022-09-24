# Deterministic PGP Keys
Generate PGP keys from a 12 word seed phrase

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

$ gpg --show-key public.asc

pub   rsa4096 2022-09-21 [C]
      96453E87B0C25A2B3E2162A441D7DC5E6E39C8A6
uid                      Jeffrey Bolle <jeffreybolle@gmail.com>
sub   rsa4096 2022-09-21 [S]
sub   rsa4096 2022-09-21 [E]
sub   rsa4096 2022-09-21 [A]

$ sha256sum public.asc private.asc
0b1ac7e12a50f1a7aac6f3bbeba195590716f6cc183fefec08c8af07e185e0f6  public.asc
e45c1fd43f5e28d4f32a49d94bedcd76351ab812b564d1315a7e391c166e5b5a  private.asc
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

$ gpg --show-key public.asc

pub   rsa4096 2022-09-21 [C]
      96453E87B0C25A2B3E2162A441D7DC5E6E39C8A6
uid                      Jeffrey Bolle <jeffreybolle@gmail.com>
sub   rsa4096 2022-09-21 [S]
sub   rsa4096 2022-09-21 [E]
sub   rsa4096 2022-09-21 [A]

$ sha256sum public.asc private.asc
0b1ac7e12a50f1a7aac6f3bbeba195590716f6cc183fefec08c8af07e185e0f6  public.asc
e45c1fd43f5e28d4f32a49d94bedcd76351ab812b564d1315a7e391c166e5b5a  private.asc
```
