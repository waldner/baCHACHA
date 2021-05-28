#!/bin/bash

# get a random amount of random bytes, then encrypt them
# with bachacha and openssl, compare the results

round=0
round_max=50

rfile=/tmp/random_file
our_file=/tmp/bachacha
openssl_file=/tmp/openssl_chacha

while [ $round -lt $round_max ]; do

  printf "Round: $round, "

  len=$(( ($SRANDOM % 500000) + 1 )) 
  echo "len: $len"

  dd if=/dev/urandom status=none bs=1 count=$len > "$rfile"

  # generate random key and iv
  key=$(dd if=/dev/urandom status=none bs=1 count=32 | xxd -p -c 32)
  iv=$(dd if=/dev/urandom status=none bs=1 count=8 | xxd -p -c 8)

  ./chacha.sh -K "$key" -I "$iv" < "$rfile" > "$our_file"
  openssl chacha20 -K "$key" -iv "0000000000000000${iv}" < "$rfile" > "$openssl_file"
  if diff -q "$our_file" "$openssl_file"; then
    result="Ok"
  else
    result="Fail"
  fi
  echo "$result"
  
  ((round++))

done

rm -rf "$rfile" "$our_file" "$openssl_file"
