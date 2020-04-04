#include <core.p4>
#include <v1model.p4>

typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

const bit<16> TYPE_IPV4 = 0x0800;
const bit<8> PROTO_UDP = 17;
const bit<8> PROTO_TCP = 0x06;

// Ethernet L2 header
header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
}

// IP L3 header
header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<6>    diffserv; // now is simply DSCP (not tos)
    bit<2>    ecn;  // borrowing 2 bits from diffserv
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
}

// UDP L4 header
header udp_t {
    bit<16> srcPort;
    bit<16> dstPort;
    bit<16> length_;
    bit<16> checksum;
}

header debug_t {
    bit<32> ws;
    // bit<48> egr_ts;
    // bit<32> dep;
    bit<32> min1;
    bit<32> min2;
    bit<32> min3;
    bit<32> min4;
    
}

struct metadata {
    bit<32> idx11;
    bit<32> idx12;
    bit<32> idx13;
    bit<32> idx14;
    
    bit<32> idx21;
    bit<32> idx22;
    bit<32> idx23;
    bit<32> idx24;
    
    bit<32> idx31;
    bit<32> idx32;
    bit<32> idx33;
    bit<32> idx34;
    
    bit<32> idx41;
    bit<32> idx42;
    bit<32> idx43;
    bit<32> idx44;

    bit<32> val11;
    bit<32> val12;
    bit<32> val13;
    bit<32> val14;
    bit<32> min1;
    
    bit<32> val21;
    bit<32> val22;
    bit<32> val23;
    bit<32> val24;
    bit<32> min2;

    bit<32> val31;
    bit<32> val32;
    bit<32> val33;
    bit<32> val34;
    bit<32> min3;
    
    bit<32> val41;
    bit<32> val42;
    bit<32> val43;
    bit<32> val44;
    bit<32> min4;

    bit<32> ws;
    bit<32> as;
    bit<32> diff;    
}

// Plain UDP packets
struct headers {
    ethernet_t ethernet;
    ipv4_t     ipv4;
    udp_t      udp;
    debug_t    debug;
}