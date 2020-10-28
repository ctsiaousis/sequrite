# OpenSSL Toolkit

This program illustrates the use cases of the EVP API from openSSL library v.1.1.1  

## Usage
```
/assign_1 -i plaintext.txt -o ciphertext.txt -p psswd -b 256 -e
```

Options: 

-i     path        Path to input file 

-p    psswd        Password for key generation 

-b    bits         Bit mode (128 or 256 only) 

-o    path         Path to output file 

-d                 Decrypt input and store results to output 

-e                 Encrypt input and store results to output 

-s                 Encrypt+sign input and store results to output 

-v                 Decrypt+verify input and store results to output 

-h                 This help message

## Details

#### Key Generation

For generating the `key` we use the 'EVP_BytesToKey' function with the `EVP_Cipher` pointing to either 128 or 256 AES_ecb cipher, depending on the mode. The `EVP_MD` pointer is set to `EVP_sha1` and we pass the input password (-p). In every case (-e/-d/-s/-v) we generate the key first, to be used in the functions.

#### Encryption

The encryption function, takes as input the contents of the input plaintext file and the key we've already generated and the bit mode we are using. It creates a new `EVP_CIPHER_CTX` and then we call the `EVP_Encrypt_Init_ex`, `EVP_EncryptUpdate` and `EVP_EncryptFinal_ex` functions. After those are done, we have the ciphertext, which length may be bigger that the plaintext. Lastly, we free the cipher content and write the ciphertext to the output file.

#### Decryption

The decryption function takes as input the contents of the input ciphertext file and the key we've already generated and the bit mode we are using. Similar to the encrypt function, we call the `EVP_Decrypt_Init_ex`, `EVP_DecryptUpdate` and `EVP_DecryptFinal_ex` functions. Then, we free the cipher context and return the length of the plaintext array, which after the function call, we write to the output plaintext file.

#### Signing

For signing we generate the ciphertext calling the encrypt function. Then, we generate the CMAC key from the plaintext. And then we concat the ciphertext and the CMAC and write those to the output file. The `gen_cmac` function, takes as input the plaintext message, it's legth, the key and the bit mode we are using. Firstly, we call the `EVP_PKEY_CTX_new_id` function and pass the `EVP_PKEY_CMAC` parameter, then we initialize the context. After, we call twice the `EVP_PKEY_CTX_ctrl` function. The first time we pass the key context and set the `EVP_PKEY_OP_KEYGEN` and `EVP_PKEY_CTRL_CIPHER` flags, setting the cipher to be AES_ecb 128/256 bits, depending on the mode. The second time we set the `EVP_PKEY_CTRL_SET_MAC_KEY` flag, and pass the key to our PKEY_CTX. Then we allocate memory for our PKEY with `EVP_PKEY_new` and then generate it with the context we previously set, using the `EVP_PKEY_keygen` function. Then, using the `EVP_DigestSignInit`, `EVP_DigestSignUpdate` and `EVP_DigestSignFinal` we create our CMAC signing of the plaintext.

#### Verification

For verifying, we take our encrypted file and sheparate the chiphertext and the CMAC. Firstly we decrypt the contents and generate the plaintext. From that plaintext we generate the CMAC using the password. Then we evaluate our generated key and the key that was originally in the file. If they are the same, the verification is complete and we save the decrypted file. If not, we inform the user and not save the file.

## Resourses

just random links that helped me throughout this process.

https://en.wikipedia.org/wiki/One-key_MAC

https://en.wikipedia.org/wiki/SHA-1

https://en.wikipedia.org/wiki/Key_derivation_function

https://datalocker.com/what-is-the-difference-between-ecb-mode-versus-cbc-mode-aes-encryption/

https://crypto.stackexchange.com/questions/225/should-i-use-ecb-or-cbc-encryption-mode-for-my-block-cipher

https://tools.ietf.org/html/rfc4493

https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation
