#include "IPv4Layer.h"
#include "TcpLayer.h"
#include "UdpLayer.h"
#include "IcmpLayer.h"
#include "Packet.h"
#include "PcapFileDevice.h"
#include <iostream>
#include <pthread.h>
#include <semaphore.h>
#include <queue>
#include <chrono>
#include <ratio>
#include <thread>
#include "count_min_sketch.hpp"

using namespace std;

queue<int> q;
sem_t full;
pthread_mutex_t mutex;
bool stop = false;
int out_limit = 125;

int h = 4, w = 4, d = 4;
int hashes[][4] = { { 0x04C11DB7, 0x0DB88320, 0x0B710641, 0x02608EDB }, { 0x041B8CD7, 0x0B31D82E, 0x0D663B05, 0x0A0DC66B }, { 0x02583499, 0x092C1A4C, 0x0D663B05, 0x0A0DC66B }, { 0x02583499, 0x04C11DB7, 0x0B710641, 0x041B8CD7 } };   
CountMinSketch c[4];

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
    int ctr = 0;
    long start_time, pkt_time = 0;
    while (reader.getNextPacket(rawPacket))
    {
        start = chrono::high_resolution_clock::now();
        if (ctr == 0) {
            timespec ts = rawPacket.getPacketTimeStamp();
            start_time = ts.tv_sec * 1e6 + ts.tv_nsec * 1e-3;
        }
        else {
            timespec ts = rawPacket.getPacketTimeStamp();
            pkt_time = ts.tv_sec * 1e6 + ts.tv_nsec * 1e-3 - start_time;
        }
        cout << pkt_time << endl;

        pthread_mutex_lock(&mutex);
        q.push(rawPacket.getRawDataLen());
        pthread_mutex_unlock(&mutex);
        sem_post(&full);

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

        ctr++;
        // cout << "Produced pkt " << ctr << " of " << rawPacket.getRawDataLen() << " bytes\n";

        end = chrono::high_resolution_clock::now();
        duration_sec = chrono::duration_cast<chrono::duration<double, milli>>(end - start);

        // cout << duration_sec.count() << endl;
    
    }

    stop = true;
    // close the file
    reader.close();
        
    
}

void* consume(void* arg) {
    int tot = 0, cnt = 0;

    while(1) {
        
        tot = 0;
        cnt = 0;

        sem_wait(&full); // wiait until queue has something
        pthread_mutex_lock(&mutex);
        cout << q.size() << endl;
        
        while (q.size() > 0 && tot < out_limit) { // 1 Gbps outgoing link speed
                
            int x = q.front();
            // cout << x << endl;
            q.pop();
            
            if (x + tot < out_limit) {
                tot += x;
                cnt += 1;
            }
            else {
                q.push(x - (out_limit - tot));
                tot += (out_limit - tot);

            }
            
        }
        pthread_mutex_unlock(&mutex);
        cout << "Consumed " << cnt << " pkts\n"; 

        std::this_thread::sleep_for(std::chrono::microseconds(250));

        if (stop && q.size() == 0)
            break;        
        
    }
}


int main(int argc, char* argv[])
{
    for (int i = 0; i < h; i++) {
        c[i].set(w, d, hashes[i]);
    }
    
    pthread_t producer,consumer;
    sem_init(&full, 0, 0);
    pthread_mutex_init(&mutex, NULL);
    pthread_create(&producer, NULL, produce, NULL);
    // pthread_create(&consumer, NULL, consume, NULL);

    pthread_join(producer, NULL);
    cout << "Producer done!\n";
    // pthread_join(consumer, NULL);
    cout << "Consumer done!\n";
    
    cout << "Exiting!!\n";

    
    return 0;
}