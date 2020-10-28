#!/bin/sh
./ssl_tool -i ../files/encryptme_256.txt -o ../files/decryptme_256.txt -p psswd -b 256 -e
./ssl_tool -i ../files/second_decryptme_128.txt -o ../files/second_encryptme_128.txt -p psswd -b 128 -d
./ssl_tool -i ../files/signme_128.txt -o ../files/verifyme_128.txt -p psswd -b 128 -s
./ssl_tool -i ../files/second_verifyme_128.txt -o ../files/second_verified_128.txt -p psswd -b 128 -v
./ssl_tool -i ../files/verifyme_256.txt -o ../files/verified_256.txt -p psswd -b 256 -v
