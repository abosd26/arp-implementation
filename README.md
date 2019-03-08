# arp-implementation
<pre>
An arp program, including functions such as listing, IP filtering, and MAC querying

Notice: The program must be executed by superuser privileges.

Usage: 1. ./arp -h => Display usages of the arp program.
       2. ./arp -l -a => Show all of the ARP packets captured by the program.
       3. ./arp -l &ltIP address&gt => Implement the filter works. Thus, it should show the ARP packets with specific target IP.
       4. ./arp -q &ltIP address&gt => Fill an ARP request packet and send it by broadcast to query the MAC address of the specific IP address.
</pre>
