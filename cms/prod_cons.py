from threading import Thread, Condition
import time
import random
from scapy.all import *

# scapy_cap = rdpcap('univ1_trace/ap_00000_20091217102604')

# No max size of queue to allow unlimited buffering, prevents pkt drops
queue = []
condition = Condition()

# byte_ctr = 0

class ProducerThread(Thread):
    def run(self):
        # global byte_ctr
        global queue
        ctr = 0
        start_time = 0
        for (pkt, meta) in RawPcapReader('univ1_trace/ap_00000_20091217102604'):
            pkt_time = 0
            if ctr == 0:
                start_time = time.time()
                pkt_init_time = meta.tshigh << 32 | meta.tslow
            else:
                pkt_time = ((meta.tshigh << 32 | meta.tslow) - pkt_init_time) * 1e-6

            # print "Wireshark ts: ", pkt_time
            
            print len(queue)
            print "Start time ", start_time
            print time.time() -start_time, pkt_time + start_time - time.time()

            if (time.time() - start_time < pkt_time):
                time.sleep(pkt_time + start_time - time.time())
            
            condition.acquire()
            queue.append(len(pkt))
            # byte_ctr += len(pkt)
            print "Produced", ctr, len(pkt)
            condition.notify()
            condition.release()
            ctr += 1
            if (ctr > 1000):
                break
            # time.sleep(random.random())

        condition.acquire()
        queue.append(-1)
        print "FIN"
        condition.notify()
        condition.release()


class ConsumerThread(Thread):
    def run(self):
        global queue
        flag = 0
        while True:
            tot = 0
            start_time = time.time()
            print "Iter starts :", start_time
            condition.acquire()
            print "Q len from consumer: ", len(queue)
            if not queue:
                print "Nothing in queue, but consumer will try to consume"
                condition.wait()
            
            while len(queue) > 0 and tot < 125:  # 1 Gbps 
                # print len(queue)
                if (queue[0] == -1):
                    flag = 1
                    break
                elif queue[0] + tot < 125:
                    tot += queue[0]
                    queue.pop(0)
                else:
                    queue[0] -= (125 - tot)
                    tot += (125 - tot)
            # time.sleep(1e-5)

            print "Consumed" 
            time.sleep(1)
            condition.release()
            print "Iter time: ", time.time() - start_time
            if flag == 1:
                break

ProducerThread().start()
# ConsumerThread().start()

ProducerThread().join()
# ConsumerThread().join()