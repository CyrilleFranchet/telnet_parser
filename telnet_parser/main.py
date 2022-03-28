#!/usr/bin/env python
# coding : utf-8

# Created by PyCharm on 28/03/2022
# Filename : main.py

from scapy.all import *
import argparse


def main():
    parser = argparse.ArgumentParser(description='Parse telnet PCAP to extract logins.')
    parser.add_argument('-f', '--file', help='PCAP file', required=True)

    args = parser.parse_args()

    pcap = rdpcap(args.file)

    list_ports = [p[TCP].sport for p in pcap if p[TCP].dport == 23]
    set_ports = set(list_ports)
    list_ports = list(set_ports)
    print(list_ports)
    print(len(list_ports))

    dict_whole = {}
    for packet in pcap:
        if packet[TCP].dport == 23 and packet.haslayer(Raw):
            if packet[TCP].sport in dict_whole:
                dict_whole[packet[TCP].sport].append(packet[Raw].load)
            else:
                dict_whole[packet[TCP].sport] = [packet[Raw].load]
        if packet[TCP].sport == 23 and packet.haslayer(Raw):
            if packet[TCP].dport in dict_whole:
                dict_whole[packet[TCP].dport].append(packet[Raw].load)
            else:
                dict_whole[packet[TCP].dport] = [packet[Raw].load]
    for port in dict_whole:
        i = 0
        for line in dict_whole[port]:
            if b'|' not in line:
                i += 1
            else:
                break
        dict_whole[port] = dict_whole[port][i:]

    number_logins = 0
    for port in dict_whole:
        next_is_login = False
        next_is_password = False
        for line in dict_whole[port]:
            try:
                line.decode()
            except UnicodeDecodeError:
                continue
            if 'metasploitable login' in line.decode():
                next_is_login = True
            elif 'Password:' in line.decode():
                next_is_password = True
            elif next_is_login:
                login = line[:-2].decode()
                next_is_login = False
            elif next_is_password:
                password = line[:-2].decode()
                next_is_password = False
                print(port, ' login:', login, ' password:', password, sep='')
                number_logins += 1
    print(number_logins, 'tries detected')


if __name__ == '__main__':
    main()
