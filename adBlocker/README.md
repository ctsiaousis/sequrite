# AdBlock via iptables

Can handle both domains and ips.

```
This script is responsible for creating a simple adblock mechanism. It rejects connections from specific domain names or IP addresses using iptables.

Usage: ./adBlocker/src/./adblock.sh  [OPTION]

Options:

  -domains    Configure adblock rules based on the domain names of 'domainNames.txt' file.
  -ips        Configure adblock rules based on the IP addresses of 'IPAddresses.txt' file.
  -save       Save rules to 'adblockRules' file.
  -load       Load rules from 'adblockRules' file.
  -list       List current rules.
  -reset      Reset rules to default settings (i.e. accept all).
  -help       Display this help and exit.
```
