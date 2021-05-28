# baCHACHA
Hot, low speed CHACHA20 encryption in Bash

### What's this?

This is an implementation of [**ChaCha20**](https://cr.yp.to/chacha.html) ([also](https://en.wikipedia.org/wiki/Salsa20#ChaCha_variant)) encryption without any external programs. No dependencies, other than a recent version of bash.

**WARNING: THIS IS EXTREMELY SLOW AND INEFFICIENT. DO NOT USE IT FOR ANY SERIOUS PURPOSE, AND DO NOT USE IT ON LARGE AMOUNTS OF DATA (EVEN _A FEW TENS_ OF KB ARE ALREADY A LOT FOR THIS BEAST). YOU HAVE BEEN WARNED.**

### Why is it "low speed"?

See the following comparison with [openssl](https://www.openssl.org/) to encrypt a file:

<pre><code>
$ <b>ls -al /bin/w</b>
-rwxr-xr-x 1 root root 22576 Feb 13 20:05 /bin/w
$ <b>time openssl chacha20 -K 9900000000000000000000000000000000000000000000000000000000000001 -iv 00000000000000002607000a00040001 < /bin/w > /dev/null</b>

real	0m0.005s
user	0m0.005s
sys	0m0.000s
$ <b>time ./chacha.sh -K 9900000000000000000000000000000000000000000000000000000000000001 -I 2607000a00040001 < /bin/w > /dev/null</b>

real	0m7.388s
user	0m7.099s
sys	0m0.140s
</code></pre>

### How do I install it?

Just run the `chacha.sh` script with the necessary arguments (see **`chacha.sh -h`** for help).

### How do I know that it produces correct results?

There are two test scripts in the `tests/` directory, whose job is to compare results from `chacha.sh` and `openssl chacha20` (see comments in the scripts). All tests should pass.
