from threading import Thread
import time
import random
from scapy.all import *
from collections import deque


# No max size of queue to allow unlimited buffering, prevents pkt drops
queue = deque()
replay = 1
out_limit = 88*2

class ProducerThread(Thread):
    def run(self):
        global queue
        ctr = 0
        start_time = 0
        pkt_time = 0
        interval = 0

        # sum_time = 0.0
        # sum_pkt_times = 2.0
        # times = 0

        for (pkt, meta) in RawPcapReader('univ1_trace/long.pcap'):
            
            if ctr == 0:
                start_time = time.time()
                pkt_init_time = meta.tshigh << 32 | meta.tslow
            else:
                pkt_time = ((meta.tshigh << 32 | meta.tslow) - pkt_init_time) * 1e-6 # in seconds
                
                # print "Wireshark ts: ", pkt_time
            
                # print "Queue len ", len(queue)
                # print "Start time ", start_time
                
                interval = time.time() - start_time
                
                # print ctr, interval, pkt_time, pkt_time*replay - interval

                if (interval < pkt_time*replay - 80e-6):
                #     print (pkt_time*replay - interval)*0.5-0.00217390060425
                    time.sleep((pkt_time*replay - interval) - 80e-6)
                # else:
                #     print "========= Caution ==========="
            
            queue.append(len(pkt))
            
            # print "Produced pkt no ", ctr, " of size ", len(pkt), " bytes"
            
            ctr += 1
            # if (ctr > 1000):
            #     break
        
        # print sum_time, sum_pkt_times
        queue.append(-1)
        # print "FIN"

class ConsumerThread(Thread):
    def run(self):
        global queue
        flag = 0
        ctr = 0
        start_time = time.time()
        while True:
            tot = 0
            cnt = 0
            # print "Iter starts :", start_time
            # if (ctr % 4 == 0):
            print len(queue)

            # print "Q len from consumer: ", len(queue)
            

            while len(queue) > 0 and tot < out_limit:  # 1 Gbps outgoing link speed
                # print len(queue)
                
                ele = queue.popleft()
                if (ele == -1):
                    flag = 1
                    break
                elif ele + tot < out_limit:
                    tot += ele
                    cnt += 1
                else:
                    queue.appendleft(ele - (out_limit - tot))
                    # tot += (125 - tot)
                    break

            # time.sleep(1e-5)

            # queue.task_done()
            
            # print "Consumed ", cnt, " pkts" 
            time.sleep(2.5e-4)
            ctr += 1
            # print "Iter time: ", time.time() - start_time
            
            if flag == 1 and len(queue) == 0:
                break

ProducerThread().start()
ConsumerThread().start()

# ProducerThread().join()
# ConsumerThread().join()