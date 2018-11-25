
import os
import sys
import socket
import socketserver
import threading
import locale
from pickle import dumps, loads
from random import random, seed, randint
from collections import deque
from queue import PriorityQueue, Queue
import logging
from datetime import datetime
import time
import concurrent.futures

SYS_ENCOD = locale.getpreferredencoding()
LAT_ENCOD = 'latin1'
DATA = 'data'
ACK = 'ack'
SYN = 'syn'
FIN = 'fin'
SEQ = 'seq'
MWS = 'mws'
PARITY = 'parity'
SEND_TIME = 'send_time'
FAST_TRANS = 'fast_trans'
SOURCE_PORT = 'source_port'
SOURCE_IP = 'source_ip'
DATA_LEN = 'data_len'
SEND = 'snd'
RECEIVE = 'rcv'
DROP = 'drop'
CORRUPT = 'corr'
DUPLICATE = 'dup'
REORDERED = 'rord'
DELAY = 'dely'
DUPLICATE_ACK = 'DA'
RETRANSMISSION = 'RXT'
SYN_EVENT = 'S'
ACK_EVENT = 'A'
DATA_EVENT = 'D'
FIN_EVENT = 'F'
logging_queue = Queue()

def make_packet(data=b'', ack=0, source_port=None, fin=False, \
    seq=random(), syn=False, fast_trans=False, mws=0, data_len=0, ip=None,send_time=datetime.now()):
    return {
    ACK: ack,
    SYN: syn,
    FIN: fin,
    SEQ: seq,
    MWS: mws,
    FAST_TRANS: fast_trans,
    SEND_TIME: send_time,
    SOURCE_PORT: source_port,
    SOURCE_IP:ip, 
    FAST_TRANS: fast_trans,
    DATA_LEN: data_len,
    DATA: data
    }

def add_data(p_dict, data):
    p_dict[DATA] = data

def p_segment(p_dict):
    return dumps(p_dict)

def parity(byte_string):
    one_gen = (bin(k).count('1') for k in byte_string)
    one_count = 0
    for k in one_gen:
        one_count += k
    return 1 if one_count%2 else 0

def corrupt(segment):
    parity_check = parity(segment[DATA])
    return 1 if parity_check != segment[PARITY] else 0

class UDPHandler(socketserver.BaseRequestHandler):
    def __init__(self, receiver, *args, **keys):
        self.receiver = receiver
        socketserver.BaseRequestHandler.__init__(self, *args, **keys)

    def handle(self):
        segment, sender_sock = _process_incoming(self.request)
        if corrupt(segment):
            event = {'event': RECEIVE+'/'+CORRUPT,'time':(datetime.now() - self.receiver.init_time).total_seconds(), 'packet_type': DATA_EVENT, 'sequence_number': segment[SEQ], 'number_of_bytes_of_data': segment[DATA_LEN], 'acknowledgment_number':segment[ACK]}
            logging_queue.put(event)
            return
        if segment[SYN]:
            event = {'event': RECEIVE,'time':(datetime.now() - self.receiver.init_time).total_seconds(), 'packet_type': SYN_EVENT, 'sequence_number': segment[SEQ], 'number_of_bytes_of_data': segment[DATA_LEN], 'acknowledgment_number':segment[ACK]}
            logging_queue.put(event)
            self.receiver.sender_address = self.client_address
            self.receiver.connected_clients.add(self.client_address)
            self.receiver.waiting_for_synack = True
            self.receiver.init_connection(segment)
        elif segment[FIN]:  
            event = {'event': RECEIVE,'time':(datetime.now() - self.receiver.init_time).total_seconds(), 'packet_type': FIN_EVENT, 'sequence_number': segment[SEQ], 'number_of_bytes_of_data': segment[DATA_LEN], 'acknowledgment_number':segment[ACK]}
            logging_queue.put(event)
            while not self.receiver.buffer.empty():
                self.receiver.drain_buffer()
                pass          

            with open(self.receiver.filename,'wb') as transfer:
                transfer.write(self.receiver.file)
            if segment[SEQ] == self.receiver.expected_seq:
                self.receiver.file = b''
                self.receiver.send_finack(segment)
                self.receiver.waiting_for_finack = True
                self.receiver.send_fin(segment)
            else:
                t = threading.Thread(target=self.receiver.handle, args=[segment])
                t.daemon =True
                t.start() 
        else: 
            if self.receiver.waiting_for_finack and segment[ACK]==self.receiver.seq_num:
                event = {'event': RECEIVE,'time':(datetime.now() - self.receiver.init_time).total_seconds(), 'packet_type': ACK_EVENT, 'sequence_number': segment[SEQ], 'number_of_bytes_of_data': segment[DATA_LEN], 'acknowledgment_number':segment[ACK]}
                logging_queue.put(event)
                
                fname = 'receiver_log.txt'
                with open(fname, 'w') as file:
                    while not logging_queue.empty():
                        event = logging_queue.get()
                        _fstring = f"{event['event']:<10} {event['time']:<10.2} {event['packet_type']:<10} {event['sequence_number']:<10} {event['number_of_bytes_of_data']:<10} {event['acknowledgment_number']} \n"
                        file.write(_fstring)
                self.receiver.server.shutdown()
                sys.exit()
                return
            t = threading.Thread(target=self.receiver.handle, args=[segment])
            t.daemon =True
            t.start()        
        return

def _process_incoming(request):
    payload = request[0].strip()
    segment = loads(payload)
    sender_socket = request[1]
    return segment, sender_socket
        
class ThreadedUDPS(socketserver.ThreadingMixIn, socketserver.UDPServer):
    daemon_threads = True
def UDPhandler_factory(callback):
    def createHandler(*args, **keys):
        return UDPHandler(callback, *args, **keys)
    return createHandler
class Receiver:
    def __init__(self, ip='localhost', port=0, filename='', server=None):
        self.ip = ip
        self.port = port
        self.filename = filename
        self.init_time = 0
        self.server = server
        self.cum_ack = None
        self.expected_seq = None
        self.seq_num = 0
        self.sender_address = None
        self.file = b''
        self.buffer = PriorityQueue()
        self.buffer_dump = []
        self.already_buffered = set()
        self.added_to_file = set()
        self.mws = 0
        self.lock = threading.RLock()
        self.connected_clients = set()
        self.waiting_for_finack = False
        self.waiting_for_synack = False

    def add_server(self, server):
        self.server = server
        self.port = self.server.server_address[1]


    def send(self, segment):
        # print(f'Sent:{segment[ACK]:>20}')
        self.server.socket.sendto(dumps(segment),self.sender_address)

    def init_connection(self, segment):
        self.sender_port = segment[SOURCE_PORT]
        self.expected_seq = segment[SEQ] + 1
        self.mws = segment[MWS]
        segment = make_packet(source_port=self.port, syn=True, seq=self.seq_num, ack=self.expected_seq)
        event = {'event': SEND,'time':(datetime.now() - self.init_time).total_seconds(), 'packet_type': SYN_EVENT+ACK_EVENT, 'sequence_number': segment[SEQ], 'number_of_bytes_of_data': segment[DATA_LEN], 'acknowledgment_number':segment[ACK]}
        logging_queue.put(event)
        self.send(segment)
        self.seq_num +=1

    def handle(self, segment):
        # print(f'Got: {segment[SEQ]:>20}')
        if corrupt(segment):
            event = {'event': RECEIVE+'/'+CORRUPT,'time':(datetime.now() - self.init_time).total_seconds(), 'packet_type': DATA_EVENT, 'sequence_number': segment[SEQ], 'number_of_bytes_of_data': segment[DATA_LEN], 'acknowledgment_number':segment[ACK]}
            logging_queue.put(event)
            self.send_dup()
            return
        
        if self.expected_seq == segment[SEQ]:
            if self.waiting_for_synack:
                if not segment[DATA]:
                    self.waiting_for_synack = False
                    event = {'event': RECEIVE,'time':(datetime.now() - self.init_time).total_seconds(), 'packet_type': ACK_EVENT, 'sequence_number': segment[SEQ], 'number_of_bytes_of_data': segment[DATA_LEN], 'acknowledgment_number':segment[ACK]}
                    logging_queue.put(event)
                    self.expected_seq = segment[SEQ] + segment[DATA_LEN]
                    return
            if self.waiting_for_finack:
                event = {'event': RECEIVE,'time':(datetime.now() - self.init_time).total_seconds(), 'packet_type': ACK_EVENT, 'sequence_number': segment[SEQ], 'number_of_bytes_of_data': segment[DATA_LEN], 'acknowledgment_number':segment[ACK]}
                logging_queue.put(event)
                return
            
            event = {'event': RECEIVE,'time':(datetime.now() - self.init_time).total_seconds(), 'packet_type': DATA_EVENT, 'sequence_number': segment[SEQ], 'number_of_bytes_of_data': segment[DATA_LEN], 'acknowledgment_number':segment[ACK]}
            logging_queue.put(event)
            self.added_to_file.add(segment[SEQ])
            self.already_buffered.add(segment[SEQ])
            self.file += segment[DATA]
            if segment[SEQ] + segment[DATA_LEN] >= self.expected_seq:
                self.expected_seq = segment[SEQ] + segment[DATA_LEN]
            self.buffer_check()
            self.send_ack(segment)
        elif self.expected_seq < segment[SEQ]:
            event = {'event': RECEIVE+'/'+DUPLICATE,'time':(datetime.now() - self.init_time).total_seconds(), 'packet_type': DATA_EVENT, 'sequence_number': segment[SEQ], 'number_of_bytes_of_data': segment[DATA_LEN], 'acknowledgment_number':segment[ACK]}
            logging_queue.put(event)
            if segment[SEQ] not in self.already_buffered:
                self.already_buffered.add(segment[SEQ])
                self.buffer.put((segment[SEQ], segment))
            self.send_dup()

    def buffer_check(self):
        if not self.buffer.empty():
            buffered_seq, buffered_seg = self.buffer.get()
            self.buffer.put((buffered_seq, buffered_seg))
            if (self.expected_seq== buffered_seq):
                self.drain_buffer() 

    def drain_buffer(self):
        seq, segment = self.buffer.get()
        byte_store = b''
        while not self.buffer.empty():
            if seq not in self.added_to_file:
                self.added_to_file.add(seq)
                byte_store += segment[DATA]
            if not self.buffer.empty():
                next_seq, next_segment = self.buffer.get()
                if next_seq > (seq+segment[DATA_LEN]):
                    self.buffer.put((next_seq, next_segment))
                    break
                if next_seq not in self.added_to_file and next_seq == (seq+segment[DATA_LEN]):
                    seq = next_seq; segment = next_segment
        if seq not in self.added_to_file:
            self.added_to_file.add(seq)
            self.file += byte_store + segment[DATA]
        else:
            self.file += byte_store
        if segment[SEQ] + segment[DATA_LEN] >= self.expected_seq:
            self.expected_seq = segment[SEQ] + segment[DATA_LEN]    
        # segment[FAST_TRANS] = 1
            
    def send_ack(self, segment):
        ack_segment = make_packet(seq=self.seq_num, ack=self.expected_seq, send_time=segment[SEND_TIME], fast_trans=segment[FAST_TRANS])
        self.send(ack_segment)
        event = {'event': SEND,'time':(datetime.now() - self.init_time).total_seconds(), 'packet_type': ACK_EVENT, 'sequence_number': ack_segment[SEQ], 'number_of_bytes_of_data': ack_segment[DATA_LEN], 'acknowledgment_number':ack_segment[ACK]}
        logging_queue.put(event)

    def send_dup(self):
        dup_segment = make_packet(seq=self.seq_num, ack=self.expected_seq)
        self.send(dup_segment)
        event = {'event': SEND+'/'+DUPLICATE_ACK,'time':(datetime.now() - self.init_time).total_seconds(), 'packet_type': ACK_EVENT, 'sequence_number': dup_segment[SEQ], 'number_of_bytes_of_data': dup_segment[DATA_LEN], 'acknowledgment_number':dup_segment[ACK]}
        logging_queue.put(event)

    def send_finack(self, segment):
        self.expected_seq +=1
        segment = make_packet(seq=self.seq_num, ack=self.expected_seq, send_time=segment[SEND_TIME])
        self.send(segment)
        event = {'event': SEND,'time':(datetime.now() - self.init_time).total_seconds(), 'packet_type': ACK_EVENT, 'sequence_number': segment[SEQ], 'number_of_bytes_of_data': segment[DATA_LEN], 'acknowledgment_number':segment[ACK]}
        logging_queue.put(event)
        
    def send_fin(self, segment):
        segment = make_packet(seq=self.seq_num, ack=self.expected_seq, send_time=segment[SEND_TIME], fin=True)
        self.send(segment)
        self.seq_num+=1
        event = {'event': SEND,'time':(datetime.now() - self.init_time).total_seconds(), 'packet_type': FIN_EVENT, 'sequence_number': segment[SEQ], 'number_of_bytes_of_data': segment[DATA_LEN], 'acknowledgment_number':segment[ACK]}
        logging_queue.put(event)


if __name__ == "__main__":
    
    args = sys.argv[1:]
    ip='localhost'
    port = int(args[0])
    receiver = Receiver(
        ip=ip,
        port=port,
        filename=args[1])
    receiver.init_time = datetime.now()
    lock = threading.Lock()
    server = ThreadedUDPS((ip, port), UDPhandler_factory(receiver))
    server.allow_reuse_address = True
    receiver.add_server(server)
    server.serve_forever()

    
    
        
