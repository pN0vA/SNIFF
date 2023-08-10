from scapy.all import sniff, TCP, IP, ICMP, sr, UDP, send
from scapy.layers.dns import DNS, DNSQR
from scapy.sendrecv import sendp
from art import *
import requests

packet_count = 0
continue_sniffing = True
total_packet_size = 0
protocol_counter = {}
captured_packets = []

def banner():
    art = text2art("SNIFF")
    print(art)
banner()

def decode_dns_payload(payload):
    try:
        dns = DNS(payload)
        if DNSQR in dns:
            return dns.qd.qname.decode("utf-8")
    except:
        pass
    return None

def save_packet(packet):
    global captured_packets
    captured_packets.append(packet)

def display_protocol_summary():
    print("\nProtocol Summary:")
    for proto, count in protocol_counter.items():
        print(f"{proto}: {count} packets")

def get_geoip_info(ip):
    url = f"http://ip-api.com/json/{ip}"
    response = requests.get(url)
    if response.status_code == 200:
        return response.json()
    return None

def perform_traceroute(dest_ip):
    print("\nPerforming Traceroute to:", dest_ip)
    tr, _ = sr(IP(dst=dest_ip, ttl=(1, 30))/ICMP(), timeout=2, verbose=False)
    tr.show()

def packet_handler(packet):
    global packet_count, continue_sniffing, total_packet_size

    if IP in packet:
        packet_count += 1
        total_packet_size += len(packet)

        src_ip = packet[IP].src
        dst_ip = packet[IP].dst
        protocol = packet[IP].proto

        # Update protocol counter
        protocol_name = protocol
        if protocol == 6 and TCP in packet:
            protocol_name = "TCP"
        elif protocol == 17 and UDP in packet:
            protocol_name = "UDP"
        elif protocol == 1 and ICMP in packet:
            protocol_name = "ICMP"

        protocol_counter[protocol_name] = protocol_counter.get(protocol_name, 0) + 1

        # DNS decoding
        if protocol == 17 and UDP in packet:
            dns_name = decode_dns_payload(packet[UDP].payload)
            if dns_name:
                print(f"DNS Request: {dns_name}")

        # GeoIP Lookup
        src_location = get_geoip_info(src_ip)
        dst_location = get_geoip_info(dst_ip)

        print("\n" + "=" * 40)
        print(f"Packet Count: {packet_count}")
        print(f"Source IP: {src_ip}")
        if src_location:
            print("Source Location:")
            for key, value in src_location.items():
                print(f"{key}: {value}")
        else:
            print("Source Location: N/A")

        print(f"Destination IP: {dst_ip}")
        if dst_location:
            print("Destination Location:")
            for key, value in dst_location.items():
                print(f"{key}: {value}")
        else:
            print("Destination Location: N/A")

        print(f"Protocol: {protocol_name}")
        print("=" * 40)

        # Save packet
        save_packet(packet)

        if protocol_name == "TCP":
            dest_port = packet[TCP].dport
            if dest_port == 80:  # HTTP
                print("Captured HTTP Packet:")
                print(packet[TCP].payload)

                # Packet Tampering
                modified_packet = packet.copy()
                modified_payload = b"Modified HTTP Payload"
                modified_packet[TCP].payload = modified_payload
                sendp(modified_packet, iface="wlan0", verbose=False)


# Start sniffing directly here
sniff(filter="ip", prn=packet_handler, timeout=60)

# After sniffing is complete, perform a traceroute
if captured_packets:
    perform_traceroute(captured_packets[-1][IP].dst)

