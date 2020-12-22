#!/bin/bash
domainNames="domainNames.txt"
IPAddresses="IPAddresses.txt"
adblockRules="adblockRules"
populateIPfile=$2 #if set, ip file will be populated from domain file

function ipFromLine {
    #sed substitute line that contains an ip with the ip only
    sed -rn 's/.*( [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+).*/\1/p'
}

function resolveDomains {
    #if populate file is set, then rewrite ips to file
    [[ $populateIPfile ]] && echo -n "" > $IPAddresses

    while read domain; do
        local ip+=( $(host $domain | ipFromLine ) )
    done < $domainNames

    i=0
    while [ $i -lt ${#ip[@]} ]; do
        #if populate file is set, then rewrite ips to file
        [[ ! -z $ip && $populateIPfile ]] && echo "${ip[$i]}" >> $IPAddresses
        # if the ip is non-empty, execute iptables.
        [[ ! -z $ip ]] && iptables -A INPUT -p all -s ${ip[$i]}  -j REJECT 
        [[ ! -z $ip ]] && iptables -A OUTPUT -p all -d ${ip[$i]}  -j REJECT
        i=$(( i + 1 ))
    done
    
    echo "[$0 -- finished successfully]" # this will echo async
}

function resolveIPs {
    while read ip; do
        #check that it seems like a valid ip and not malicious command, then execute iptables.
        echo $ip | grep -E -q "([0-9]{1,3}[\.]){3}[0-9]{1,3}" && iptables -A INPUT -p all -s $ip -j REJECT
        echo $ip | grep -E -q "([0-9]{1,3}[\.]){3}[0-9]{1,3}" && iptables -A OUTPUT -p all -d $ip -j REJECT 
    done < $IPAddresses

    echo "[$0 -- finished successfully]" # this will echo async
}

function adBlock() {
    if [ "$EUID" -ne 0 ];then
        printf "Please run as root.\n"
        exit 1
    fi
    if [ "$1" = "-domains"  ]; then
        # Configure adblock rules based on the domain names of $domainNames file.
        echo "Running in background, you will be noticed upon termination."
        resolveDomains &
        true

    elif [ "$1" = "-ips"  ]; then
        # Configure adblock rules based on the IP addresses of $IPAddresses file.
        echo "Running in background, you will be noticed upon termination."
        resolveIPs &
        true
        
    elif [ "$1" = "-save"  ]; then
        # Save rules to $adblockRules file.
        iptables-save > $adblockRules
        true
        
    elif [ "$1" = "-load"  ]; then
        # Load rules from $adblockRules file.
        iptables-restore < $adblockRules
        true
        
    elif [ "$1" = "-reset"  ]; then
        # Reset rules to default settings (flush IN/OUT chain rules).
        iptables -F INPUT
        iptables -F OUTPUT
        true
        
    elif [ "$1" = "-list"  ]; then
        # List current rules.
        iptables -L --line-numbers
        true
        
    elif [ "$1" = "-help"  ]; then
        printf "This script is responsible for creating a simple adblock mechanism. It rejects connections from specific domain names or IP addresses using iptables.\n\n"
        printf "Usage: $0  [OPTION]\n\n"
        printf "Options:\n\n"
        printf "  -domains\t  Configure adblock rules based on the domain names of '$domainNames' file.\n"
        printf "  -ips\t\t  Configure adblock rules based on the IP addresses of '$IPAddresses' file.\n"
        printf "  -save\t\t  Save rules to '$adblockRules' file.\n"
        printf "  -load\t\t  Load rules from '$adblockRules' file.\n"
        printf "  -list\t\t  List current rules.\n"
        printf "  -reset\t  Reset rules to default settings (i.e. accept all).\n"
        printf "  -help\t\t  Display this help and exit.\n"
        exit 0
    else
        printf "Wrong argument. Exiting...\n"
        exit 1
    fi
}

adBlock $1
exit 0