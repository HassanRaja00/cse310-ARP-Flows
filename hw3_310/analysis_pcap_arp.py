import dpkt

class AnalyzeArp:
    def __init__(self, pcapfile):
        self.file = pcapfile

    def readFile(self):
        num_arp_messages = 0
        with open(self.file, 'rb') as self.file:
            pcap = dpkt.pcap.Reader(self.file)
            for ts, buf in pcap:
                #  first determine if packet is ARP or not (arp packets type is 2054 or 0x0806)
                packet_type = int.from_bytes(buf[12:14], byteorder='big')
                if packet_type == 2054 and num_arp_messages < 3:  # this will make sure it only prints first exchange
                    num_arp_messages += 1
                    protocol = int.from_bytes(buf[16:18], byteorder='big')
                    hardware_type = int.from_bytes(buf[14:16], byteorder='big')
                    type = int.from_bytes(buf[20:22], byteorder='big')  # 1 is req, 2 is res (opcode, or operation)
                    # sender_mac_addr = int.from_bytes(buf[22:28], byteorder='big')
                    # sender_ip_addr = int.from_bytes(buf[28:32], byteorder='big') NOT SURE IF THESE ARE NEEDED
                    target_mac_addr = int.from_bytes(buf[32:38], byteorder='big')
                    # target_ip_addr = int.from_bytes(buf[38:42], byteorder='big')

                    print("Hardware Type: " + str(hardware_type) + " (" + hex(hardware_type) + ")")
                    print("Protocol Type: " + str(protocol) + " (" + hex(protocol) + ")")
                    print("Hardware size: " + str(buf[18]))
                    print("Protocol size: " + str(buf[19]))
                    if type == 1:
                        print("ARP packet type/opcode: " + str(type) + " (request)")
                    else:
                        print("ARP packet type/opcode: " + str(type) + " (response)")
                    print("Sender MAC address: " + format(buf[22], '02x') + ":" + format(buf[23], '02x') + ":" + format(buf[24], '02x') + ":" +
                          format(buf[25], '02x') + ":" + format(buf[26], '02x') + ":" + format(buf[27], '02x'))
                    print("Sender IP address: " + str(buf[28]) + "." + str(buf[29]) + "." + str(buf[30]) + "." + str(buf[31]))
                    if target_mac_addr == 0:
                        print("Target MAC address: 00:00:00:00:00:00 (unknown at this moment)")
                    else:
                        print("Target MAC address: " + format(buf[32], '02x') + ":" + format(buf[33], '02x') + ":" + format(buf[34], '02x') + ":" +
                            format(buf[35], '02x') + ":" + format(buf[36], '02x') + ":" + format(buf[37], '02x'))
                    print("Target IP address: " + str(buf[38]) + "." + str(buf[39]) + "." + str(buf[40]) + "." + str(buf[41]))
                    print("num ARP packets read so far: " + str(num_arp_messages))
                    print('\n')
                else:
                    continue



if __name__ == "__main__":
    file = AnalyzeArp("assignment3_my_arp.pcap")
    file.readFile()