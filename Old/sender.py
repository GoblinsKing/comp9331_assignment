
import os
import sys
import socket
import socketserver
import threading
import locale
from pickle import dumps, loads
from random import random, seed, randint, uniform
from time import sleep
from collections import OrderedDict
from collections import deque
import logging
from datetime import datetime
import time
from queue import Queue
logging_queue = Queue()

SYS_ENCOD = locale.getpreferredencoding()
LAT_ENCOD = 'latin1'
DATA = 'data'
ACK = 'ack'
SYN = 'syn'
FIN = 'fin'
SEQ = 'seq'
MWS ='mws'
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
SYN_ON = 1
SYN_OFF = 0
MIN_PORT = 1025
MAX_PORT = 6500
INIT_TIMEOUT = 0.5
INIT_DUP_ACK = 0
EST_RTT = 0.5
DEV_RTT = 0.25
ONE_MINUS_ALPHA = 0.875
ALPHA = 0.125
ONE_MINUS_BETA = 0.75
BETA = 0.25
MILLISECONDS = 1000
PDROP = 'pDrop'
PDUPLICATE = 'pDuplicate'
PCORRUPT = 'pCorrupt'
PORDER = 'pOrder'
PDELAY = 'pDelay'



def ceildiv(a, b):
    return -(-a // b)
def parity(byte_string):
    one_gen = (bin(k).count('1') for k in byte_string)
    one_count = 0
    for k in one_gen:
        one_count += k
    return 1 if one_count%2 else 0
    
class InteruptableTimer(threading.Thread, threading.Event):
    def __init__(self, init_timeout=1, sender=None, segment=None):
        self.timer_stop = threading.Event()
        self._timeout = init_timeout
        self.t = None
        self.sender = sender


    def timer(self):
        while not self.timer_stop.is_set():
            got_stopped = self.timer_stop.wait(timeout=self.timeout)
            if got_stopped:
                break
            elif not got_stopped:
                if self.sender.pending_acks and not self.sender.transmission_terminated:
                    self.sender.timeout_retransmissions +=1
                    segment = self.sender.pending_acks[0][1]
                    event = {'event': SEND,'time':(datetime.now() - self.sender.init_time).total_seconds(), 'packet_type': DATA_EVENT, 'sequence_number': segment[SEQ], 'number_of_bytes_of_data': segment[DATA_LEN], 'acknowledgment_number':segment[ACK]}
                    logging_queue.put(event)
                    segment[FAST_TRANS]=0
                    self.sender.send(segment)
                    self.start()
                break

    def start(self):
        if self.t is not None and self.t.is_alive():
            self.stop()
        self.t = threading.Thread(target=self.timer, daemon=True)
        self.timer_stop.clear()
        self.t.start()

    def stop(self):
        self.timer_stop.set()
        
    @property
    def timeout(self):
        return self._timeout

    @timeout.setter
    def timeout(self, value):
        if value > 3:
            self._timeout = 3
        elif value < .2:
            self._timeout = .2
        else:
            self._timeout = value
        return

class UDPHandler(socketserver.BaseRequestHandler):
    def __init__(self, sender, *args, **keys):
        self.sender = sender
        socketserver.BaseRequestHandler.__init__(self, *args, **keys)

    def handle(self):
        segment, receiver_sock = _process_incoming(self.request)

        if segment[SYN]:
            self.sender.receiver_address = self.client_address
            self.sender.complete_shake(segment)
        elif segment[FIN]:
            self.sender.send_finack(segment)
            self.sender.transmission_terminated = True
            try:
                self.sender.server.server_close()
            except:
                pass
            self.sender.timer.stop()
            fname = 'sender_log.txt'
            with open(fname, 'w') as file:
                while not logging_queue.empty():
                    event = logging_queue.get()
                    width = 10
                    prec = .2
                    _fstring = f"{event['event']:<10} {event['time']:<10.2} {event['packet_type']:<10} {event['sequence_number']:<10} {event['number_of_bytes_of_data']:<10} {event['acknowledgment_number']} \n"
                    file.write(_fstring)
                file.write('\n')
                file.write('Total segments transfered: {}\n'.format(self.sender.total_segments_sent))
                file.write('Size of file: {}\n'.format(self.sender.size_of_file))
                file.write('Elapsed time: {}\n'.format(datetime.now() - self.sender.init_time))
                file.write('Total segments dropped: {}\n'.format(self.sender.total_dropped))
                file.write('Total segments duplicated: {}\n'.format(self.sender.total_duplicates))
                file.write('Total segments corrupted: {}\n'.format(self.sender.total_corrupted))
                file.write('Total segments reordered: {}\n'.format(self.sender.total_reordered))
                file.write('Total segments delayed: {}\n'.format(self.sender.total_delayed))
            self.sender.server.shutdown()
            sys.exit()
        else:
            server_thread = threading.Thread(target=self.sender.handle, args=[segment])
            server_thread.daemon = True 
            server_thread.start()        
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

def decor_func(original_function):
    def wrapper(*args, **kwargs):
        if DATA in kwargs:
            data_len = len(kwargs[DATA])
            par = parity(kwargs[DATA])
        else:
            data_len = 0
            par = 0
        send_time = datetime.now()
        
        return original_function(data_len=data_len,send_time=send_time,parity=par, *args, **kwargs)
    return wrapper
    
@decor_func
def make_packet(data=b'', ack=0, source_port=None, fin=False, \
    seq=random(), syn=False, fast_trans=False, mws=0, data_len=0, ip=None,send_time=datetime.now(), parity=0):
    return {
    ACK: ack,
    SYN: syn,
    FIN: fin,
    SEQ: seq,
    MWS: mws,
    PARITY: parity,
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


class Sender():
    def __init__(self,ip, port, mws=None, mss=None, gamma=None, server=None, filename='', pDrop=0, pDuplicate=0, pCorrupt=0, pOrder=0, pDelay=0, maxOrder=0,maxDelay=0):
        self.init_time = 0
        self.pld = {PDROP: pDrop, PDUPLICATE: pDuplicate, PCORRUPT: pCorrupt, PORDER: pOrder, PDELAY: pDelay}
        self.re_order = []
        self.max_delay = maxDelay
        self.max_order = maxOrder
        self.filename = filename
        self.finished_sending = False
        self.waiting_for_fin = False
        self.waiting_for_finack = False
        self.receiver_ip = ip
        self.receiver_port = port
        self.receiver_address= None
        self.address = (self.receiver_ip, self.receiver_port)
        self.mws = mws
        self.mss = mss
        self.gamma = gamma
        self.server = server
        self.window_size = 0
        self.send_base = False
        self.seq_num = 0
        self.port = None
        self.pending_acks = deque()
        self.timer = InteruptableTimer(self)
        self.dup_ack = [0, 0]
        self.receiver_seq = None
        self.lock = threading.Lock()
        self.connected_clients = set()
        self.sample_rtt = 0
        self.transmission_terminated = False
        self.size_of_file = 0
        self.total_segments_sent = 0
        self.timeout_retransmissions = 0
        self.fast_retransmissions = 0
        self.total_dupacks = 0
        self.total_duplicates = 0
        self.total_delayed = 0
        self.total_dropped = 0
        self.total_corrupted = 0
        self.total_reordered = 0
        self._estimated_rtt = EST_RTT
        self._dev_rtt = DEV_RTT
        self._timeout = self._estimated_rtt + self.gamma * self._dev_rtt

    @property
    def estimated_rtt(self):
        return ONE_MINUS_ALPHA* self._estimated_rtt + ALPHA*self.sample_rtt

    @property
    def dev_rtt(self):
        return ONE_MINUS_BETA* self._dev_rtt + BETA*abs(self.sample_rtt - self.estimated_rtt)

    @property    
    def timeout(self):
        return self.estimated_rtt + self.gamma * self.dev_rtt

    def send(self, segment):
        if (self.timer.t==None) or not self.timer.t.is_alive():
            self.timer.timeout = self.timeout
            self.timer.start()
        self.total_segments_sent += 1
        
        self.server.socket.sendto(dumps(segment), self.address)

    def complete_shake(self, segment):
        event = {'event': RECEIVE,'time':(datetime.now() - self.init_time).total_seconds(), 'packet_type': SYN_EVENT + ACK_EVENT, 'sequence_number': segment[SEQ], 'number_of_bytes_of_data': segment[DATA_LEN], 'acknowledgment_number':segment[ACK]}
        logging_queue.put(event)
        self.connected_clients.add(self.receiver_address)
        self.receiver_seq = segment[SEQ]+1
        segment = make_packet(source_port=self.port, syn=False, seq=self.seq_num, ack=self.receiver_seq)
        self.send(segment)
        event = {'event': SEND,'time':(datetime.now() - self.init_time).total_seconds(), 'packet_type': ACK_EVENT, 'sequence_number': segment[SEQ], 'number_of_bytes_of_data': segment[DATA_LEN], 'acknowledgment_number':segment[ACK]}
        logging_queue.put(event)
        self.start_transfer()
        self.send_fin()
        
    def init_connection(self):
        segment = make_packet(source_port=self.port, syn=True, \
            seq=self.seq_num, mws=self.mws)
        self.pending_acks.append((self.seq_num, segment))
        self.send_base = self.seq_num
        self.dup_ack = [self.seq_num, 0]
        self.send(segment)
        event = {'event': SEND,'time':(datetime.now() - self.init_time).total_seconds(), 'packet_type': SYN_EVENT, 'sequence_number': segment[SEQ], 'number_of_bytes_of_data': segment[DATA_LEN], 'acknowledgment_number':segment[ACK]}
        logging_queue.put(event)
        self.seq_num +=1

    def start_transfer(self):
        stats = os.stat(self.filename)
        num_segs = ceildiv(stats.st_size, self.mss)
        self.read_in_file(num_segs)

    def handle(self, segment):
        '''Check if the ACK is greater than the current lowest acknowleded ACK(send_base). If it is, we can remove the segments from our pending acknowledgement dictionary. If not, we increment the duplicate acknowledgement counter for that segment.'''

        if segment[ACK] > self.send_base:
            '''Iterate through the pending acknowledgemnt dcitionary to pop the segments who's sequence number is lower - cumulative acknowledgements.'''
            self.send_base = segment[ACK]
            self.dup_ack = [segment[ACK], 0]

            event = {'event': RECEIVE,'time':(datetime.now() - self.init_time).total_seconds(), 'packet_type': ACK_EVENT, 'sequence_number': segment[SEQ], 'number_of_bytes_of_data': segment[DATA_LEN], 'acknowledgment_number':segment[ACK]}
            logging_queue.put(event)
            while self.pending_acks and self.pending_acks[0][0] < self.send_base:
                if self.pending_acks:
                    segment_tuple = self.pending_acks.popleft()
                else:
                    break
                if segment_tuple[1][SEND_TIME] == segment[SEND_TIME] and not segment[FAST_TRANS]:
                    self.sample_rtt = (datetime.now() - segment[SEND_TIME]).total_seconds()
                    self._estimated_rtt
                    self._dev_rtt 
                self.window_size -= segment_tuple[1][DATA_LEN]
            if (self.timer.t==None) or not self.timer.t.is_alive():
                self.timer.timeout = self.timeout
                self.timer.start()
        else:
            '''Fast retransmitting section. Increment the counter, if more than three have been recieved then send the segment again.'''
            event = {'event': RECEIVE +'/' + DUPLICATE_ACK,'time':(datetime.now() - self.init_time).total_seconds(), 'packet_type': ACK_EVENT, 'sequence_number': segment[SEQ], 'number_of_bytes_of_data': segment[DATA_LEN], 'acknowledgment_number':segment[ACK]}
            self.lock.acquire()
            logging.info('SYNACK SENT',extra=event)
            self.lock.release()
            self.total_dupacks +=1
            if self.dup_ack[0] == segment[ACK]:
                self.dup_ack[1] +=1
            if self.dup_ack[1] == 3:
                fast_seg = self.pending_acks[0][1]
                fast_seg[FAST_TRANS] = 1
                self.dup_ack[1] = 0
                self.fast_retransmissions += 1
                event = {'event': SEND+'/'+RETRANSMISSION,'time':(datetime.now() - self.init_time).total_seconds(), 'packet_type': DATA_EVENT, 'sequence_number': fast_seg[SEQ], 'number_of_bytes_of_data': fast_seg[DATA_LEN], 'acknowledgment_number':fast_seg[ACK]}
                logging_queue.put(event)
                self.send(fast_seg)
                

    def add_server(self, server):
        self.server = server
        self.port = self.server.server_address[1]
        server_thread = threading.Thread(target=self.server.serve_forever)
        server_thread.daemon = True 
        server_thread.start()

    def send_fin(self):
        segment = make_packet(seq=self.seq_num, fin=True, ack=self.receiver_seq)
        self.waiting_for_fin = True
        self.send(segment)
        self.pending_acks.append((self.seq_num, segment))
        self.seq_num+=1
        event = {'event': SEND,'time':(datetime.now() - self.init_time).total_seconds(), 'packet_type': FIN_EVENT, 'sequence_number': segment[SEQ], 'number_of_bytes_of_data': segment[DATA_LEN], 'acknowledgment_number':segment[ACK]}
        logging_queue.put(event)

    def send_finack(self, segment):
        event = {'event': RECEIVE,'time':(datetime.now() - self.init_time).total_seconds(), 'packet_type': FIN_EVENT, 'sequence_number': segment[SEQ], 'number_of_bytes_of_data': segment[DATA_LEN], 'acknowledgment_number':segment[ACK]}
        logging_queue.put(event)
        self.receiver_seq+=1
        segment = make_packet(seq=self.seq_num, ack=self.receiver_seq)
        self.send(segment)
        self.pending_acks.append((self.seq_num, segment))
        event = {'event': SEND,'time':(datetime.now() - self.init_time).total_seconds(), 'packet_type': ACK_EVENT, 'sequence_number': segment[SEQ], 'number_of_bytes_of_data': segment[DATA_LEN], 'acknowledgment_number':segment[ACK]}
        logging_queue.put(event)

    def read_in_file(self, num_segs):
        with open(self.filename, mode='rb') as file:
            for k in range(0, num_segs):
                payload = file.read(self.mss)
                self.size_of_file += len(payload)
                while len(payload)+ self.window_size >= self.mws:
                    '''Essentially pauses the program until segements have been acknowledged and the window size shrinks.
                    FUTURE/TODO: Set a global timeout so that the ports dont get blocked if this loop never ends'''
                    pass
                segment = make_packet(seq=self.seq_num, data=payload, ack=self.receiver_seq)
                self.pending_acks.append((self.seq_num, segment))
                self.pld_module(segment)
                self.seq_num = self.seq_num+len(payload)
                self.window_size += len(payload)

                if (self.timer.t==None) or not self.timer.t.is_alive():
                    self.timer.timeout = self.timeout
                    self.timer.start()
            self.finished_sending = True
    def pld_module(self, segment):
        prop = random()
        segment[FAST_TRANS]=1
        if prop < self.pld[PDROP]:
            event = {'event': DROP,'time':(datetime.now() - self.init_time).total_seconds(), 'packet_type': DATA_EVENT, 'sequence_number': segment[SEQ], 'number_of_bytes_of_data': segment[DATA_LEN], 'acknowledgment_number':segment[ACK]}
            logging_queue.put(event)
            self.total_dropped +=1
            return
        prop = random()
        if prop < self.pld[PDUPLICATE]:
            event = {'event': SEND,'time':(datetime.now() - self.init_time).total_seconds(), 'packet_type': DATA_EVENT, 'sequence_number': segment[SEQ], 'number_of_bytes_of_data': segment[DATA_LEN], 'acknowledgment_number':segment[ACK]}
            logging_queue.put(event)
            event = {'event': SEND+'/'+DUPLICATE,'time':(datetime.now() - self.init_time).total_seconds(), 'packet_type': DATA_EVENT, 'sequence_number': segment[SEQ], 'number_of_bytes_of_data': segment[DATA_LEN], 'acknowledgment_number':segment[ACK]}
            logging_queue.put(event)
            self.total_duplicates +=1
            segment[FAST_TRANS]=0
            self.send(segment)
            self.re_order_check()
            segment[FAST_TRANS]=1
            self.send(segment)
            self.re_order_check()
            return 
        prop = random()    
        if prop < self.pld[PCORRUPT]:
            event = {'event': SEND+'/'+CORRUPT,'time':(datetime.now() - self.init_time).total_seconds(), 'packet_type': DATA_EVENT, 'sequence_number': segment[SEQ], 'number_of_bytes_of_data': segment[DATA_LEN], 'acknowledgment_number':segment[ACK]}
            logging_queue.put(event)
            self.total_corrupted +=1
            segment[PARITY] = ~segment[PARITY]
            self.send(segment)
            self.re_order_check()
            return 
        segment[FAST_TRANS]=0 
        prop = random()    
        if prop < self.pld[PORDER]:
            if not self.re_order:
                self.re_order = [segment, 0]
                self.total_reordered +=1
                return
        segment[FAST_TRANS]=0
        prop = random()    
        if prop < self.pld[PDELAY]:
            
            sd = threading.Thread(target=self.send_with_delay, args=[segment], daemon=True)
            self.total_delayed +=1
            sd.start()
            return
        
        event = {'event': SEND,'time':(datetime.now() - self.init_time).total_seconds(), 'packet_type': DATA_EVENT, 'sequence_number': segment[SEQ], 'number_of_bytes_of_data': segment[DATA_LEN], 'acknowledgment_number':segment[ACK]}
        logging_queue.put(event)
        self.send(segment)
        self.re_order_check()
        return

    def send_with_delay(self, segment):
        delay = uniform(0, self.max_delay)/MILLISECONDS
        time.sleep(delay)
        event = {'event': SEND+'/'+DELAY,'time':(datetime.now() - self.init_time).total_seconds(), 'packet_type': DATA_EVENT, 'sequence_number': segment[SEQ], 'number_of_bytes_of_data': segment[DATA_LEN], 'acknowledgment_number':segment[ACK]}
        logging_queue.put(event)
        self.send(segment)
        self.re_order_check()
    
    def re_order_check(self):
        if not self.re_order:
            return
        self.re_order[1] +=1
        if self.re_order[1]>=self.max_order:
            event = {'event': SEND+'/'+REORDERED,'time':(datetime.now() - self.init_time).total_seconds(), 'packet_type': DATA_EVENT, 'sequence_number': self.re_order[0][SEQ], 'number_of_bytes_of_data': self.re_order[0][DATA_LEN], 'acknowledgment_number':self.re_order[0][ACK]}
            logging_queue.put(event)
            self.send(self.re_order[0])
            self.re_order = []

if __name__ == "__main__":
    args = sys.argv[1:]
    my_address = ('localhost', 0)
    sender = Sender(
        ip=args[0], 
        port=int(args[1]), 
        filename=args[2], 
        mws=int(args[3]), 
        mss=int(args[4]),
        gamma=float(args[5]),
        pDrop=float(args[6]),
        pDuplicate=float(args[7]),
        pCorrupt=float(args[8]),
        pOrder=float(args[9]),
        maxOrder=int(args[10]),
        pDelay=float(args[11]),
        maxDelay=float(args[12])
        )
    seed(int(args[13]))
    sender.init_time = datetime.now()
    sender.timer.sender = sender
    server = ThreadedUDPS(my_address, UDPhandler_factory(sender))
    server.allow_reuse_address = True   
    sender.add_server(server)
    sender.init_connection()
    server.serve_forever()  