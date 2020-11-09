# RSA
This project is a key generation, encryption and decryption, using the RSA algorithm, from scratch.

## Key Generation
We first calculate the first prime numbers until 255 using the `sieve of Eratosthenes` algorithm.

Then we pick two random cells from that table as the primes `p` and `q`.

We calculate `n = p * q` and also phi of n based on the Euler’s totient function, `fi_n = (p-1)*(q-1)`.

Then we choose a prime e that is `2<e<fi_n`, and `(e%fi(n)!=0) AND (gcd(e,fi(n))==1)` where gcd() is the Greatest Common Denominator.

Lastly, we calculate `d`, as the modular inverse of `e` and `fi_n`.

The public key generated is `n,d`.  
The private key generated is `n,e`.  

## Encryption
After we read the inputFile and the keyFile we allocate space for our cipherText buffer and calculate for each cell of the message buffer  

`
cipher[i]=(message[i]^key[1]) % key[0]
`

where `0<=i<message_length`, `key[0] = n` and `key[1] = d / e` depending on the key input.

## Decryption
After we read the inputFile and the keyFile we allocate space for our messageText buffer and calculate for each cell of the cipherText buffer  

`
message[i]=(cipher[i]^key[1]) % key[0]
`

where `0<=i<message_length`, `key[0] = n` and `key[1] = d / e` depending on the key input.


## Example

```         
Usage:
             ./rsa_tool -g -v
             ./rsa_tool -i in_file -o out_file -k key_file [-d | -e]
             ./rsa_tool -h
             
Options:
          -i    path    Path to input file
          -o    path    Path to output file
          -k    path    Path to key file
          -d            Decrypt input and store results to output
          -e            Encrypt input and store results to output
          -g            Generates a keypair and saves to 2 files
          -v            Verbose output
          -h            This help message
```