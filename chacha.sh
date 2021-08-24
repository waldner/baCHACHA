#!/bin/bash

######### General global variables and constants ###############

declare -a CHACHA_state
declare -a CHACHA_input
declare -a CHACHA_stream   # used to encrypt input
declare -a CHACHA_output
declare CHACHA_bytes_read

CHACHA_block_size=64

# used only for base64 output
declare -a CHACHA_base64_table
CHACHA_base64_table=( A B C D E F G H I J K L M N O P Q R S T U V W X Y Z
                   a b c d e f g h i j k l m n o p q r s t u v w x y z
                   0 1 2 3 4 5 6 7 8 9 + / )

CHACHA_base64_left=0
CHACHA_base64_index=0
CHACHA_base64_columns=64
CHACHA_base64_cur_columns=0

CHACHA_show_help(){
  {
    echo "Usage: $0 -K <key> [ -I <IV> ] [ -c <counter> ] [ -o raw|hex|base64 ] [ -d ] [ -h ]"
    echo 
    echo "-K <key>     key to use for encryption. Mandatory. Must be a hexadecimal string (eg"
    echo "             '03a2b8ef888a901193a2000f883a9ff1aa331483af32997e' for 256 bit). If it's"
    echo "             not exactly 32 bytes (256 bits), will be padded with zeros or truncated as needed."
    echo "-I <iv>      Initialization vector to use (AKA 'nonce'). Must be a hexadecimal"
    echo "             string. Will be padded with zeros or truncated if length is not 8 bytes"
    echo "-c <counter> Initial value for the counter (default 0)."
    echo "-o <format>  Output format. Must be one of 'raw', 'hex' or 'base64'. Default: 'raw'."
    echo "-h           Show this help."
    echo 
    echo "EXAMPLES"
    echo
    echo "$0 -K '38742984797292987837878abf736aff38df29847222929877a7899abf736af1' -I '1234567890123456' -c 1 < file1.plain > file1.encrypted"
    echo "$0 -K 'abc7192840000000111122aaaaaaaa0900000000000000000000000000000a00' -I '00' < file2.encrypted > file2.plain"
  } >&2
}

CHACHA_log(){
  printf '%s\n' "$1" >&2
}

CHACHA_die(){
  CHACHA_log "$1"
  exit 1
}

CHACHA_base64_print(){
  local char=$1
  printf '%s' "$char"
  ((CHACHA_base64_cur_columns++))
  if [ $CHACHA_base64_cur_columns -ge $CHACHA_base64_columns ]; then
    printf '\n'
    CHACHA_base64_cur_columns=0
  fi
}

# outputs elements of array up to "$last" in base64 format.
# "streaming" base64 in bash. Really.
CHACHA_output_base64(){

  local i
  local -n array=$1
  local last=$2

  for ((i = 0; i < last; i++)); do
    if [ $CHACHA_base64_index -eq 0 ]; then
      CHACHA_base64_print "${CHACHA_base64_table[${array[i]} >> 2]}"
      CHACHA_base64_left=$(( (array[i] & 3) << 4))
    elif [ $CHACHA_base64_index -eq 1 ]; then
      CHACHA_base64_print "${CHACHA_base64_table[$CHACHA_base64_left + (${array[i]} >> 4)]}"
      CHACHA_base64_left=$(( (array[i] & 15) << 2 ))
    elif [ $CHACHA_base64_index -eq 2 ]; then
      CHACHA_base64_print "${CHACHA_base64_table[$CHACHA_base64_left + (${array[i]} >> 6)]}"
      CHACHA_base64_print "${CHACHA_base64_table[${array[i]} & 63]}"
      CHACHA_base64_left=0
    fi

    # we must maintain state between calls
    CHACHA_base64_index=$(( (CHACHA_base64_index + 1) % 3))

  done
}

CHACHA_output_base64_finalize(){

  if [ $CHACHA_base64_index -eq 1 ]; then
    CHACHA_base64_print "${CHACHA_base64_table[$CHACHA_base64_left]}"
    CHACHA_base64_print "="
    CHACHA_base64_print "="
  elif [ $CHACHA_base64_index -eq 2 ]; then
    CHACHA_base64_print "${CHACHA_base64_table[$CHACHA_base64_left]}"
    CHACHA_base64_print "="
  fi

  if [ $CHACHA_base64_cur_columns -ne 0 ]; then
    printf '\n'
  fi
}

CHACHA_read_input(){

  local data length bytes status
  local fd=$1

  bytes=0

  local to_read=$CHACHA_block_size   # 64, regardless of bits

  CHACHA_eof=0

  while true; do

    IFS= read -u $fd -d '' -r -n $to_read data
    status=$?

    length=${#data}

    for ((i=0; i < length; i++)); do
      printf -v "CHACHA_input[bytes+i]" "%d" "'${data:i:1}"
    done

    # if we read less than we wanted, and it's not EOF, it means we also have
    # a delimiter (NUL)
    if [ $length -lt $to_read ] && [ $status -eq 0 ]; then
      CHACHA_input[bytes+length]=0
      ((length++))
      #echo "Read NUL"
    fi

    ((bytes+=length))
    if [ $bytes -ge $CHACHA_block_size ]; then
      break
    fi
    if [ $status -ne 0 ]; then
      CHACHA_eof=1
      break
    fi
    ((to_read-=length))
  done

  CHACHA_bytes_read=$bytes

}

# outputs elements of array up to "$last" in raw format
CHACHA_output_raw(){
  local -n array=$1
  local last=$2

  if [ $last -gt 0 ]; then
    printf "$(printf '\\x%x' "${array[@]:0:$last}")"
  fi
}

# outputs elements of array up to "$last" in hex format
CHACHA_output_hex(){
  local -n array=$1
  local last=$2

  if [ $last -gt 0 ]; then
    printf '%02x' "${array[@]:0:$last}"
    printf '\n'
  fi
}

CHACHA_init(){

  local hex_key=$1
  local hex_iv=$2
  local key_length iv_length i j tmp

  # check key length
  key_length=$(( ${#hex_key} / 2 ))

  if [ $key_length -lt 32 ] || [ $key_length -gt 32 ]; then
    CHACHA_log "Warning: forcing key length to 256 bits (32 bytes)"
  fi
  hex_key="${hex_key}0000000000000000000000000000000000000000000000000000000000000000"
  hex_key=${hex_key:0:64}

  # IV must always be 8 bytes
  iv_length=$(( ${#hex_iv} / 2 ))

  if [ $iv_length -lt 8 ] || [ $iv_length -gt 8 ]; then
    CHACHA_log "Warning: forcing IV to 64 bits (8 bytes)"
  fi
  hex_iv="${hex_iv}0000000000000000"
  hex_iv=${hex_iv:0:16}


  # init state

  local const="expand 32-byte k"   # 128 bit

  # take the 16 chars of the constant 4 by four; each group of 4 must be reversed
  # and turned into a 32-bit int

  for ((i = 0; i < ${#const}; i+=4)); do
    CHACHA_state[i/4]=0
    for ((j=3; j >= 0; j--)); do
      printf -v tmp "%d" "'${const:i+j:1}"
      CHACHA_state[i/4]=$(( CHACHA_state[i/4] + (tmp << (j*8)) ))
    done
  done

  # next is the key (256 bit): same thing
  for ((i = 0; i < ${#hex_key}; i+=8)); do
    CHACHA_state[4+(i/8)]=0
    for ((j=6; j >= 0; j-=2)); do
      tmp=$(( 16#${hex_key:i+j:2} ))
      CHACHA_state[4+(i/8)]=$(( CHACHA_state[4+(i/8)] + (tmp << ((j/2)*8)) ))
    done
  done

  # next is the counter
  if [ $CHACHA_counter -le $(( 2 ^ 32 - 1 )) ]; then
    # use byte 12 only
    CHACHA_state[12]=$CHACHA_counter
    CHACHA_state[13]=0
  else
    CHACHA_state[12]=$(( CHACHA_counter & 16#ffffffff ))
    CHACHA_state[13]=$(( CHACHA_counter >> 32 ))
  fi

  # next is the iv or nonce (64 bit)
  for ((i = 0; i < ${#hex_iv}; i+=8)); do
    CHACHA_state[14+(i/8)]=0
    for ((j=6; j >= 0; j-=2)); do
      tmp=$(( 16#${hex_iv:i+j:2} ))
      CHACHA_state[14+(i/8)]=$(( CHACHA_state[14+(i/8)] + (tmp << ((j/2)*8)) ))
    done
  done

}

CHACHA_rotl(){
  local -n ar=$1
  local i=$2 bits=$3
  ar[i]=$(( (ar[i] << bits | (ar[i] >> (32 - bits))) & 16#ffffffff )) 
}


CHACHA_QR(){

  # indexes inside state_copy
  local a=$2 b=$3 c=$4 d=$5
  local -n arr=$1

  arr[a]=$(( (arr[a] + arr[b]) & 16#ffffffff ))
  ((arr[d]^=arr[a]))
  CHACHA_rotl arr $d 16

  arr[c]=$(( (arr[c] + arr[d]) & 16#ffffffff ))
  ((arr[b]^=arr[c]))
  CHACHA_rotl arr $b 12

  arr[a]=$(( (arr[a] + arr[b]) & 16#ffffffff ))
  ((arr[d]^=arr[a]))
  CHACHA_rotl arr $d 8

  arr[c]=$(( (arr[c] + arr[d]) & 16#ffffffff ))
  ((arr[b]^=arr[c]))
  CHACHA_rotl arr $b 7

}


CHACHA_scramble_state(){

  local round i j tmp
  local -a state_copy

  # state is in CHACHA_state, make a copy
  state_copy=( "${CHACHA_state[@]}" )

  # scramble the state with 10 double rounds
  for ((round = 0; round < 10; round++)); do
    CHACHA_QR state_copy 0 4 8 12
    CHACHA_QR state_copy 1 5 9 13
    CHACHA_QR state_copy 2 6 10 14
    CHACHA_QR state_copy 3 7 11 15

    CHACHA_QR state_copy 0 5 10 15
    CHACHA_QR state_copy 1 6 11 12
    CHACHA_QR state_copy 2 7 8 13
    CHACHA_QR state_copy 3 4 9 14
  done

  # sum the scrambled state to the original to get the 
  # actual stream
  for ((i = 0; i < ${#state_copy[@]}; i++)); do
    tmp=$(( (state_copy[i] + CHACHA_state[i]) & 16#ffffffff ))
    # transform to bytes to encrypt input
    for ((j = 0; j < 4; j++)); do
      CHACHA_stream[(i*4)+j]=$(( (tmp & (16#ff << (j*8) )) >> (j*8) ))
    done
  done

}


CHACHA_do_encrypt(){

  local fd=0

  while true; do
    CHACHA_read_input $fd    # input into CHACHA_input
    CHACHA_scramble_state

    # do the actual enctrpytion of CHACHA_input with CHACHA_stream
    # result goes into CHACHA_output

    for ((i = 0; i < CHACHA_bytes_read; i++)); do
      CHACHA_output[i]=$(( CHACHA_input[i] ^ CHACHA_stream[i] ))
    done

    $CHACHA_output_function CHACHA_output $CHACHA_bytes_read
    if [ $CHACHA_eof -eq 1 ]; then
      break
    fi

    # increase counter
    CHACHA_state[12]=$(( (CHACHA_state[12] + 1) & 16#ffffffff ))
    if [ ${CHACHA_state[12]} -eq 0 ]; then
      CHACHA_state[13]=$(( (CHACHA_state[13] + 1) & 16#ffffffff ))
    fi

  done

  if [ "$CHACHA_output_format" = "base64" ]; then
    CHACHA_output_base64_finalize   # this needs no args
  fi
}


################################################################
####################### BEGIN ##################################
################################################################

export LC_ALL=C

# default values
CHACHA_output_format=raw
hex_key=
hex_iv=
CHACHA_counter=0

while getopts ":K:I:c:o:h" opt; do
  case $opt in
    K)
      hex_key=$OPTARG
      ;;
    I)
      hex_iv=$OPTARG
      ;;
    c)
      CHACHA_counter=$OPTARG
      ;;
    o)
      CHACHA_output_format=$OPTARG
      ;;
    h)
      CHACHA_show_help
      exit
      ;;
    \?)
      echo "Invalid option: -$OPTARG" >&2
      exit 1
      ;;
    :)
      echo "Option -$OPTARG requires an argument." >&2
      exit 1
      ;;
  esac
done

# sanity checks
if [[ ! "$CHACHA_output_format" =~ ^(hex|raw|base64)$ ]]; then
  CHACHA_die "Invalid output format '$CHACHA_output_format', terminating"
else
  CHACHA_output_function=CHACHA_output_${CHACHA_output_format}
fi

if [ "$hex_key" = "" ]; then
  CHACHA_die "Must specify hex key (-K)"
else
  hex_key=${hex_key,,?}
  # check that key is a valid length
  if [ $(( ${#hex_key} % 2 )) -ne 0 ] || [[ ! "${hex_key}" =~ ^[0-9a-f]+$ ]]; then
    CHACHA_die "Hex key must be an even number of hex chars (0-9a-f)"
  fi
fi

if [ "$hex_iv" = "" ]; then
  CHACHA_die "Must specify IV"
else
  hex_iv=${hex_iv,,?}
  # check that iv is a valid length
  if [ $(( ${#hex_iv} % 2 )) -ne 0 ] || [[ ! "${hex_iv}" =~ ^[0-9a-f]+$ ]]; then
    CHACHA_die "Hex IV must be an even number of hex chars (0-9a-f)"
  fi
fi

# prepare key and stuff
CHACHA_init "$hex_key" "$hex_iv"

# if we get here, we're doing real work. Check that neither stdin nor stdout (raw
# mode only) is connected to terminal
if [ -t 0 ]; then
  CHACHA_die "No input (stdin)"
fi

if [ "$CHACHA_output_format" = "raw" ] && [ -t 1 ]; then
  CHACHA_die "Won't write raw bytes to terminal, if you really want to do it pipe to cat, or switch to hex or base64 output"
fi

# Encryption and decryption are the same. This is nice
CHACHA_do_encrypt

exit
