#!/bin/bash

export LD_PRELOAD=./logger.so

dirName=./testFiles
numOfFiles=30

[ -d $dirName ] || mkdir $dirName

j=0
while [ $j -le $numOfFiles ]; do
#    touch "$dirName/file_$j.txt"
    echo "very precious file, number $j." > "$dirName/file_$j.txt"
    j=$(( j + 1 ))
done

j=0
while [ $j -le $numOfFiles ]; do
    openssl enc -aes-256-ecb -in "$dirName/file_$j.txt" -out "$dirName/file_$j.txt.encrypt" -k "1234" 2> /dev/null
    rm -f "$dirName/file_$j.txt"
    j=$(( j + 1 ))
done

echo "Give me your bitcoins!"
