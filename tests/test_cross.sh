#!/bin/bash

# get a random amount of random bytes, then encrypt them
# with openssl and decrypt with bachacha, and viceversa

round=0
round_max=50

rfile=/tmp/random_file
our_file_enc=/tmp/bachacha_enc
openssl_file_enc=/tmp/openssl_chacha_enc
our_file_dec=/tmp/bachacha_dec
openssl_file_dec=/tmp/openssl_chacha_dec

while [ $round -lt $round_max ]; do

  printf "Round: $round, "

  len=$(( ($SRANDOM % 500000) + 1 )) 
  echo "len: $len"

  dd if=/dev/urandom status=none bs=1 count=$len > "$rfile"

  # generate random key and iv
  key=$(dd if=/dev/urandom status=none bs=1 count=32 | xxd -p -c 32)
  iv=$(dd if=/dev/urandom status=none bs=1 count=8 | xxd -p -c 8)

  # encrypt with bachacha, decrypt with openssl
  ./chacha.sh -K "$key" -I "$iv" < "$rfile" > "$our_file_enc"
  openssl chacha20 -K "$key" -iv "0000000000000000${iv}" -d < "$our_file_enc" > "$openssl_file_dec"
  if diff -q "$rfile" "$openssl_file_dec"; then
    result="Ok"
  else
    result="Fail"
  fi
  echo "$result"

  # encrypt with openssl, decrypt with bachacha
  # this is really not needed, since encryption and decryption are the same algorithm
  openssl chacha20 -K "$key" -iv "0000000000000000${iv}" < "$rfile" > "$openssl_file_enc"
  ./chacha.sh -K "$key" -I "$iv" < "$openssl_file_enc" > "$our_file_dec"
  if diff -q "$rfile" "$our_file_dec"; then
    result="Ok"
  else
    result="Fail"
  fi
  echo "$result"
  
  ((round++))

done

rm -rf "$rfile" "$our_file_dec" "$openssl_file_dec" "$our_file_enc" "$openssl_file_enc"

