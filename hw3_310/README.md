To run my program, put any pcap file into the main method. My program will then
read the bytes and display the details of only the first ARP exchange,
and will count the number of ARP packets. <br />
My answer to part b (iii) is here: <br />
IP of my router is 192.168.29.1<br />
MAC of my router is 38:2c:4a:96:bf:e8<br />
Explanation: ARP requests are always sent as broadcasts because the target MAC address is not known. Since it is broadcasted,
	     every other device on the LAN will receive the message. All the devices except one will notice that when they
	     received the ARP request, the message was intended for another device with the IP address 192.168.29.1. The router,
	     which is configured to 192.168.29.1 will notice that the message is for itself, and will construct an ARP reply
	     saying basically "My IP address is 192.168.29.1 and my MAC address is 38:2c:4a:96:bf:e8".