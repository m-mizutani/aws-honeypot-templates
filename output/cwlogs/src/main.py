#!/usr/bin/env python

import logging
import json
import ipaddress
import base64
from curses import ascii

import dpkt
import boto3

logger = logging.getLogger()
logger.setLevel(logging.INFO)


def extract_stream_info(pcap):
    base_seq, src_addr, dst_port = None, None, None
    init_ts, last_ts = None, None
    segments = []

    for ts, buf in pcap:
        if not init_ts:
            init_ts = ts
        last_ts = ts

        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type != 2048:
            continue

        ip = eth.data
        if not src_addr:
            src_addr = ipaddress.IPv4Address(ip.src)

        if ip.p != 6:
            continue

        tcp = ip.data
        if not dst_port:
            dst_port = tcp.dport
        if not base_seq:
            base_seq = tcp.seq
            if tcp.flags & dpkt.tcp.TH_SYN > 0:
                base_seq += 1

        segments.append((tcp.seq - base_seq, tcp.data))

    payload = b''
    ptr = 0
    for seg in sorted(segments, key=lambda x: x[0]):
        if ptr < seg[0]:
            payload += b'\x00' * (seg[0] - ptr) + seg[1]
            ptr = seg[0] + len(seg[1])
        elif seg[0] < ptr:
            s = seg[1][ptr-seg[0]:]
            payload += s
            ptr += len(s)
        else:
            payload += seg[1]
            ptr += len(seg[1])

    return init_ts, last_ts, src_addr, dst_port, payload


def byte_to_readable(bdata):
    s = ''
    for b in bdata:
        if ascii.isprint(b) or ascii.isspace(b):
            s += chr(b)
        else:
            s += '.'

    return s


def handler(event, context):
    logger.info("%s", json.dumps(event))
    results = []

    for pcap in extract_pcap_data(event):
        init_ts, last_ts, src_addr, dst_port, payload = extract_stream_info(
            pcap)
        log = {
            'init_ts': init_ts,
            'last_ts': last_ts,
            'src_addr': str(src_addr),
            'dst_port': dst_port,
            'payload': base64.b64encode(payload).decode('utf8'),
            'readable': byte_to_readable(payload),
        }
        results.append(log)

    logger.info("result = %s", json.dumps(results))
    return results


def extract_pcap_data(sns_event):
    s3 = boto3.client('s3')

    for sns_record in sns_event.get('Records', []):
        msg = sns_record['Sns']['Message']
        s3event = json.loads(msg)

        for s3_record in s3event['Records']:
            logger.info("s3record = %s", json.dumps(s3_record))

            resp = s3.get_object(Bucket=s3_record['s3']['bucket']['name'],
                                 Key=s3_record['s3']['object']['key'])
            logger.info('s3 reponse: %s', resp)
            pcap = dpkt.pcap.Reader(resp['Body'])
            yield pcap
