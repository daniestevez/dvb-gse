#!/usr/bin/env python3

# Copyright (c) 2024 Daniel Estevez <daniel@destevez.net>
#
# SPDX-License-Identifier: MIT OR Apache-2.0
#
#
# This test script generates GSE-HEM BBFRAMEs containing IPv6 UDP packets of
# random sizes and sends the BBFRAMEs in UDP packets to 127.0.0.1:2000.
#

import random
import socket
import struct
import time

from scapy.layers.inet import UDP
from scapy.layers.inet6 import IPv6


def crc8(data):
    reg = 0
    for d in data:
        for j in range(8):
            b = (d >> (7 - j)) & 1
            feed = (reg >> 7) ^ b
            reg = (reg << 1) & 0xff
            if feed:
                reg ^= 0b1101_0101
    return reg


def generate_packet(serial):
    server_ip = 'fe80::1'
    client_ip = 'fe80::2'
    server_port = 12345
    client_port = 54321
    data_len = random.randrange(1500)
    data = (struct.pack('>I', serial)
            + bytes([j & 0xff for j in range(data_len - 4)]))
    packet = (IPv6(src=server_ip, dst=client_ip)
              / UDP(sport=server_port, dport=client_port)
              / data)
    return packet


def generate_gse_packet(serial):
    protocol_type = struct.pack('>H', 0x86DD)  # ipv6
    ip_packet = bytes(generate_packet(serial))
    gse_length = 2 + len(ip_packet)
    return (struct.pack('>H', gse_length | (0b1110 << 12))
            + protocol_type
            + ip_packet)


def main():
    UDP_IP = '127.0.0.1'
    UDP_PORT = 2000

    frame_error_rate = 0.0

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    remain = b''
    dfl_bytes = 2000
    dfl_bits = dfl_bytes * 8
    # To be filled with SYNCD and CRC-8 ^ MODE
    bbheader_template = bytearray(
        bytes.fromhex('ba 00 00 00 00 00 00 00 00 00'))
    bbheader_template[4] = dfl_bits >> 8
    bbheader_template[5] = dfl_bits & 0xff
    bbheader_template = bytes(bbheader_template)
    serial = 0
    while True:
        syncd = len(remain) * 8
        bbheader = bytearray(bbheader_template)
        bbheader[7] = syncd >> 8
        bbheader[8] = syncd & 0xff
        crc = crc8(bbheader[:9])
        bbheader[9] = crc ^ 1
        bbframe = bytes(bbheader) + remain
        remain = b''

        while len(bbframe) < len(bbheader_template) + dfl_bytes:
            packet = bytes(generate_gse_packet(serial))
            serial += 1
            to_take = min(len(packet),
                          dfl_bytes - (len(bbframe) - len(bbheader_template)))
            bbframe += packet[:to_take]
            if to_take < len(packet):
                remain = packet[to_take:]

        drop = random.random() < frame_error_rate
        if not drop:
            sock.sendto(bbframe, (UDP_IP, UDP_PORT))
        time.sleep(0.1)


if __name__ == '__main__':
    main()
