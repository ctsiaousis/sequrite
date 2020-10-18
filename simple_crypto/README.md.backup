# Simple Crypto Library

This library is the implementation of three simple cipher algorithms

* One-Time Pad
* Caesar's cipher
* Vigenère’s cipher

___

### What's inside

You can find four files. The `simple_crypto.h` and `simple_crypto.c` are the headers and the implementations of the library, accordingly. Also the `demo.c` is, as the name suggests, a demo programm that uses the library. Lastly the `Makefile` builds those all together, using usefull security-driven CFLAGS, to create a single executable named `demo`.

___

## Implementation Designs

#### General

* Dynamic memory allocation for the input.
 
We initially allocate `INITIAL_SIZE` bytes for each field of unsigned chars. As we read the input we check if only one cell remains in the array. In this case we allocate space double the `INITIAL_SIZE` and then make the last cell of the array to point to the new location.

```
+---+---+---+---+---+---+---+
| 1 | s | t | A | r | r | *-|------+
+---+---+---+---+---+---+---+	   |
								   V
								 +---+---+---+---+---+---+---+---+---+---+...
								 | n | e | w | A | l | l | o | c | a | t | i  o  n
   								 +---+---+---+---+---+---+---+---+---+---+...
```
This functionality is implemented in the `readInput` and `readCaps` functions.

*Note:* that this could be implemented a little bit better. We could store the next two values and see if the last is `\0` or `\n`. in this case, we could avoid allocating more space.

* Syscall Managment

For not blowing our code with checks for each system call, I've implemented a simple function that takes an int and a text. If the int is not -1 it returns its vallue. If it is, it prints the text using `perror` and exits. The function name is `checkSysCall`

#### One-Time Pad

This algorithm uses `/dev/urandom` the linux device that produces random bytes. The keys are organized in a *struct* named `OneTimePad` and its members are : the input, the secretKey, the output and also the length of the input for convenience.

It utillizes a function named `getNcharsFromURandom` that reads N-bytes from the device and stores it in the secKey field of the struct. And another function named `otpEncrypt` that returns to the output the result of the `input` **xor** `secKey`. The same function is also used for decrypting.

*Note:* that the encrypted value isn't always a printable character, so we print its hex value.

#### Caesar's cipher

All data is organised in the `struct CaesarsChipher`.
 
This specific implementation uses the characters `0 to 9`, `A to Z` and `a to z`. So our alphabet is 62 characters and if we go and do this "hardcoded" on ASCII values we would create a mess.

An elegant turnaround for this is to translate the ASCII values to our own, continuous, charset.

```
+-----+-----+----+-----+-----+-----+----+-----+----+-----+-----+----+-----+
| 0   |     | 48 |     | 57  |     | 65 |     | 90 |     | 97 |     | 122 | ASCII values
|-----|-----|----|-----|-----|-----|----|-----|----|-----|----|-----|-----|
| ... | ... | 0  | ... | 9   | ... | A  | ... | Z  | ... | a  | ... | z   |	characters
|-----|-----|----|-----|-----|-----|----|-----|----|-----+-----+----+-----+
| 0   |     | 10 | 11  |     | 36  | 37 |     | 62 | Custom values
|-----|-----|----|-----|-----|-----|----|-----|----|
| 0   | ... | 9  | A   | ... | Z   | a  | ... | Z  | characters
+-----+-----+----+-----+-----+-----+----+-----+----+
```

As shown we translate the ASCII values to our `0 to 62` value charset. Then we do the shifts as we were implementing a regular Caesar's cipher, and then we retranslate them to ASCII.

The reverse is the same procedure.

The use of the above is implemented in the `caesarsCipher` function which takes as an arguement our whole `struct CaesarsChipher` and a bool to indicate en/decryption.

#### Vigenère’s cipher

All data is organised in the `struct VigeneresChipher`. For this cipher we only accept capital letters, so we find use for the function `readCaps`. We read the input and then the key. If the key is bigger than the input, we only take the size of input as the key array. If it is smaller, we just adjust which bytes we take in the en/decrypt funtion by taking the possition i modulo the keySize.

