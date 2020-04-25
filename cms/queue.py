from threading import Thread
import time
import random
from scapy.all import *


# No max size of queue to allow unlimited buffering, prevents pkt drops
queue = Queue()
replay = 100

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

        for (pkt, meta) in RawPcapReader('univ1_trace/ap_00000_20091217102604'):
            
            if ctr == 0:
                start_time = time.time()
                pkt_init_time = meta.tshigh << 32 | meta.tslow
            else:
                pkt_time = ((meta.tshigh << 32 | meta.tslow) - pkt_init_time) * 1e-6
                
                # print "Wireshark ts: ", pkt_time
            
                # print "Queue len ", queue.qsize()
                # print "Start time ", start_time
                
                interval = time.time() - start_time
                
                print ctr, interval, pkt_time, pkt_time*replay - interval

                # if (interval < pkt_time*replay):
                #     print (pkt_time*replay - interval)*0.5-0.00217390060425
                time.sleep((pkt_time*replay - interval)*0.5)
                # else:
                #     print "========= Caution ==========="
            
            queue.put(len(pkt))
            
            # print "Produced", ctr, len(pkt)
            
            ctr += 1
            # if (ctr > 1000):
            #     break
        
        # print sum_time, sum_pkt_times
        queue.put(-1)
        print "FIN"

class ConsumerThread(Thread):
    def run(self):
        global queue
        flag = 0
        while True:
            tot = 0
            start_time = time.time()
            print "Iter starts :", start_time
            
            print "Q len from consumer: ", len(queue)
            
            while queue.qsize() > 0 and tot < 125:  # 1 Gbps outgoing link speed
                # print len(queue)
                
                ele = queue.get()
                if (ele == -1):
                    flag = 1
                    break
                elif ele + tot < 125:
                    tot += ele
                else:
                    queue.put(ele - (125 - tot))
                    tot += (125 - tot)

            # time.sleep(1e-5)

                queue.task_done()
            print "Consumed" 
            time.sleep(1)
            print "Iter time: ", time.time() - start_time
            
            if flag == 1:
                break

ProducerThread().start()
ConsumerThread().start()

# ProducerThread().join()
# ConsumerThread().join()