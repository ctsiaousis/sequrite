# Sniffer

A packet sniffing tool, base on pcap library.

---

The only difference between the file and device mode is how i initialize the pcap handle.
After that i call pcap_loop with a callback, and have the same set of functions for packet processing in both modes.
The general idea is take the raw byte array of the packet and move the pointer based on the size of each nested internet protocol header.

For the flow handling, i have a list of flow tuples, with the extra info of `last_seq_number` and `numberOfRetransmissions`.
In the UDP protocol we cannot tell if the packet is retransmitted because we do not have any error handling defined in the protocol
and the header is much smaller. In TCP,on the other hand, we do. We have the seq and ack numbers. There are two ways to detect the retransmission.
One is the case that two packets are sent on the same time and the receiver returns only one acknowledgment. We do not check this case since we
define the network flows as one-directional. The case that we do check is that the SEQ number, in the same flow, is suddenly smaller than the
previous.

Tip: define `INTERACTIVE_MODE` to be asked for flow printing after execution.
