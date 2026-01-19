from scapy.all import IP, TCP, UDP, Ether, wrpcap

def generate_pcap():
    packets = []
    # TCP Flow
    packets.append(Ether()/IP(src="192.168.1.1", dst="192.168.1.2")/TCP(sport=1234, dport=80, flags="S"))
    packets.append(Ether()/IP(src="192.168.1.2", dst="192.168.1.1")/TCP(sport=80, dport=1234, flags="SA"))
    packets.append(Ether()/IP(src="192.168.1.1", dst="192.168.1.2")/TCP(sport=1234, dport=80, flags="A"))
    
    # UDP Flow
    packets.append(Ether()/IP(src="10.0.0.1", dst="10.0.0.2")/UDP(sport=5000, dport=6000)/"Hello World")
    
    output_file = "test_traffic.pcap"
    wrpcap(output_file, packets)
    print(f"Generated {output_file}")

if __name__ == "__main__":
    generate_pcap()
