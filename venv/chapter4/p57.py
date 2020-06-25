from scapy.all import *

def package_callback(packet):

    mail_packet= str(packet[TCP].payload)
    if 'user' in mail_packet.lower() or "pass" in mail_packet.lower():

        print "[*] Server: %s" % packet[IP].dst
        print "[*] %s" % packet[TCP].payload

sniff(filter="tcp port 110 or tcp port 25 or tcp port 143", prn=package_callback, store=0)



