#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "UdpLayer.h"
#include "IcmpLayer.h"
#include "Packet.h"
#include "PcapFileDevice.h"
#include <iostream>
#include <pthread.h>
#include <semaphore.h>
#include <deque>
#include <queue>
#include <chrono>
#include <ratio>
#include <thread>
#include <unordered_map>
#include "count_min_sketch.hpp"

using namespace std;

deque<pair<int, vector<uint32_t>>> q;
queue<int> wsq;
sem_t full;
pthread_mutex_t mutex;
bool stop = false;
int out_limit = 72;
double replay = 0.54;
int sleep_time;

int h, w, d = 4, k = 16;
double alpha;
int num_pkts;
int hashes[][4] = { { 0x04C11DB7, 0x0DB88320, 0x0B710641, 0x02608EDB }, { 0x041B8CD7, 0x0B31D82E, 0x0D663B05, 0x0A0DC66B }, { 0x02583499, 0x092C1A4C, 0x0D663B05, 0x0A0DC66B }, { 0x02583499, 0x04C11DB7, 0x0B710641, 0x041B8CD7 } };   
CountMinSketch c[64]; // h snapshots
vector<unordered_map<string, int>> vm(64);
unordered_map<string, int> distinct;
int rep_contri = 0, actual_contri = 0, g_contri = 0;


void* produce(void* arg) {

    chrono::high_resolution_clock::time_point start;
    chrono::high_resolution_clock::time_point end;
    chrono::duration<double, milli> duration_sec;
    
    // open a pcap file for reading
    pcpp::PcapFileReaderDevice reader("../cms/univ1_trace/long.pcap");
    if (!reader.open())
    {
        printf("Error opening the pcap file\n");
        return (void*)1;
    }

    pcpp::RawPacket rawPacket;
    int ctr = 0, maxm = 0;
    long start_time, pkt_time = 0;

    while (reader.getNextPacket(rawPacket))
    {
        if (ctr == 0) {
            timespec ts = rawPacket.getPacketTimeStamp();
            start_time = ts.tv_sec * 1e6 + ts.tv_nsec * 1e-3; // microseconds
            start = chrono::high_resolution_clock::now();
        }
        else {
            timespec ts = rawPacket.getPacketTimeStamp();
            pkt_time = ts.tv_sec * 1e6 + ts.tv_nsec * 1e-3 - start_time; // microseconds
            
            end = chrono::high_resolution_clock::now();
            duration_sec = chrono::duration_cast<chrono::duration<double, milli>>(end - start);
            
            int durn = (pkt_time*replay - duration_sec.count()*1e3)-80;
            std::this_thread::sleep_for(std::chrono::microseconds(durn));
        }
        
        pcpp::Packet parsedPacket(&rawPacket);

        pcpp::IPv4Address srcIP("1.2.3.4"), destIP("5.6.7.8");
        uint16_t srcPort = 1234, dstPort = 5678;
        uint8_t protocol = 10;
        
        if (parsedPacket.isPacketOfType(pcpp::IPv4))
        {
            // extract source and dest IPs
            srcIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getSrcIpAddress();
            destIP = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getDstIpAddress();
            protocol = parsedPacket.getLayerOfType<pcpp::IPv4Layer>()->getProtocol();
            if (protocol == (uint8_t)6) {
                srcPort = parsedPacket.getLayerOfType<pcpp::TcpLayer>()->getTcpHeader()->portSrc;
                dstPort = parsedPacket.getLayerOfType<pcpp::TcpLayer>()->getTcpHeader()->portSrc;
            }

            if (protocol == (uint8_t)17) {
                srcPort = parsedPacket.getLayerOfType<pcpp::UdpLayer>()->getUdpHeader()->portSrc;
                dstPort = parsedPacket.getLayerOfType<pcpp::UdpLayer>()->getUdpHeader()->portDst;
            }

        }
        // Put all other ARP / ICMP packets in the same flow class

        pthread_mutex_lock(&mutex);
        // cout << "Queue size : " << q.size() << endl;
        int sz = q.size();
        maxm = max(maxm, sz);
        
        string key = to_string(srcIP.toInt())+to_string(destIP.toInt())+to_string(protocol)+to_string(srcPort)+to_string(dstPort);

        // Write to snapshot
        int write_stage = (ctr/num_pkts)%h;
        // c[write_stage].view_snapshot();
        c[write_stage].update(srcIP.toInt(), destIP.toInt(), protocol, srcPort, dstPort);
        // c[write_stage].view_snapshot();
        
        // Ground truth DS for accounting
        vm[write_stage][key]+= 1;
        distinct[key] += 1;
        vector<uint32_t> arr({srcIP.toInt(), destIP.toInt(), protocol, srcPort, dstPort});
        q.push_back({rawPacket.getRawDataLen(), arr});
        wsq.push(write_stage);
        
        // Read from snapshots
        int read_limit = ((ctr-sz)/num_pkts)%h;
        int read = 0;

        if ((read_limit+1)%h == write_stage) {
            read = c[read_limit].estimate(srcIP.toInt(), destIP.toInt(), protocol, srcPort, dstPort);
        }
        
        else if (read_limit != write_stage) {
            // int start = (read_limit+1)%h;
            int start = read_limit;
            int end = (write_stage - 1 + h)%h;
            
            for (int i = start; ; i = (i+1)%h) {
                int read_curr = c[i].estimate(srcIP.toInt(), destIP.toInt(), protocol, srcPort, dstPort);
                read += read_curr;
                
                // c[i].view_snapshot();
                if (i == end)
                    break;
            }
            // if (read > distinct[key])
                // cout << "Overestimate " << start << " " << end << endl;
        }

        bool true1 = (sz > 50) && ((double)read/(double)sz > alpha);
        bool true2 = (sz > 50) && ((double)distinct[key]/(double)sz > alpha);

        if (sz > 50) {
            // cout << read << " " << distinct[key] << " " << sz << " " << (double)read/(double)sz << " " << (double)distinct[key]/(double)sz << endl;
        }
        
        if (true1 && true2) {
            actual_contri++;
        }

        if (true1) {
            rep_contri++;
        }

        if (true2) {
            // cout << read << " " << distinct[key] << " " << sz << " " << (double)read/(double)sz << " " << (double)distinct[key]/(double)sz << endl;
            g_contri++;
        }

        // if (g_contri > 0 && ctr % 50 == 0) {
        //     double precision = rep_contri ? (double)actual_contri/(double)rep_contri : 1.0;
        //     cout << (double)actual_contri/(double)g_contri << " " << precision << endl;
        // }


        // Clear snapshots
        for (int i = 0; i < d; i++) {
            for (int j = 0; j < k; j++)
                c[(write_stage+1)%h].C[i][(k*ctr+j)%w] = 0;
        }

        pthread_mutex_unlock(&mutex);


        ctr++;
        // cout << "Produced pkt " << ctr << " of " << rawPacket.getRawDataLen() << " bytes\n";

        // cout << duration_sec.count() << endl;
    
    }

    stop = true;
    // close the file
    reader.close();
    if (maxm > num_pkts * (h-2))
        cerr << "=== Error === " << endl;
    // cerr << actual_contri << " " << rep_contri << " " << g_contri << endl;    
    // cerr << "Precision : " << (double)actual_contri/(double)rep_contri << ", Recall : " << (double)actual_contri/(double)g_contri << endl;
    cout << (double)actual_contri/(double)rep_contri << endl;
    // cerr << maxm << endl;
    
}

void* consume(void* arg) {
    int tot = 0, cnt = 0, ctr = 0, maxm = 0;

    while(1) {
        
        tot = 0;
        cnt = 0;

        // sem_wait(&full); // wait until queue has something
        pthread_mutex_lock(&mutex);
        // cout << q.size() << endl;

        while (q.size() > 0 && tot < out_limit) { // 1 Gbps outgoing link speed
                
            auto ele = q.front();
            int x = ele.first;
            // cout << x << endl;
            q.pop_front();

            if (x + tot < out_limit) {
                tot += x;
                cnt += 1;
                string key = to_string(ele.second[0])+to_string(ele.second[1])+to_string(ele.second[2])+to_string(ele.second[3])+to_string(ele.second[4]);
                
                // if (vm[wsq.front()].find(key) == vm[wsq.front()].end()) {
                //     cout << "-------------- Key NOT FOUND --------------\n";
                //     cout << ele.second[0] << " " << ele.second[1] << " " << ele.second[2] << " " << ele.second[3] << " " << ele.second[4] << endl;
                // }

                // if (vm[wsq.front()][key] == 0)
                //     cout << "============ Major error ===============\n";
                
                vm[wsq.front()][key] -= 1;
                distinct[key] -= 1;
                if (distinct[key] == 0)
                    distinct.erase(key);
                wsq.pop();
            }
            else {
                q.push_front({x - (out_limit - tot), ele.second});
                tot += (out_limit - tot);

            }
            
        }
        pthread_mutex_unlock(&mutex);
        // cout << "Consumed " << cnt << " pkts\n"; 

        std::this_thread::sleep_for(std::chrono::microseconds(sleep_time));

        if (stop && q.size() == 0)
            break;  

        ctr += 1;      
        
    }

    // cout << distinct.size() << endl;
}


int main(int argc, char* argv[])
{
    h = atoi(argv[1]);
    w = atoi(argv[2]);
    num_pkts = 2048/h;
    sleep_time = 82;
    if (h == 32)
        sleep_time = 78;
    if (h == 64)
        sleep_time = 56;
    alpha = atof(argv[3]);
    for (int i = 0; i < h; i++) {
        c[i].set(w, d, hashes[i%4]);
    }
    // cout << c[6 ].hashes[d-1] << endl;
    
    pthread_t producer,consumer;
    // sem_init(&full, 0, 0);
    pthread_mutex_init(&mutex, NULL);
    pthread_create(&producer, NULL, produce, NULL);
    pthread_create(&consumer, NULL, consume, NULL);

    pthread_join(producer, NULL);
    // cout << "Producer done!\n";
    pthread_join(consumer, NULL);
    // cout << "Consumer done!\n";
    
    // cout << "Exiting!!\n";

    
    return 0;
}