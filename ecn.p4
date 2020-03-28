#include <core.p4>
#include <v1model.p4>
#include "headers.p4"
#include "parser.p4"

typedef bit<9>  egressSpec_t;

const bit<19> ECN_THRESHOLD = 5;
const bit<32> E2E_CLONE_SESSION_ID = 500;
const bit<32> BMV2_V1MODEL_INSTANCE_TYPE_EGRESS_CLONE = 2;

control ingress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) {

	action no_op() {}

	action drop() {
        mark_to_drop(standard_metadata);
    }

	action ipv4_forward(bit<9> port) {
		standard_metadata.egress_spec = port;
		// Not making modifications to L2 MAC addresses
		hdr.ipv4.ttl = hdr.ipv4.ttl - 1;
	}

	table ipv4_fwd {
		key = {
			hdr.ipv4.dstAddr : exact;
		}
		actions = {
			ipv4_forward;
			drop;
			no_op;
		}
		default_action = no_op();
	}

	apply {
		// No need to check for valid ipv4 header

		// put pkt on destined egress port
		ipv4_fwd.apply();		
	}



}


// No checksum verification
control vrfy(inout headers h, inout metadata meta) { apply {} }

// No checksum update
control updt(inout headers h, inout metadata meta) { apply {} }

// No per-port specific modification in egress
control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) { 
	action mark_ecn() {
		hdr.ipv4.ecn = 3;
	}

	apply {
		// Cloned pkt
		if (standard_metadata.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_EGRESS_CLONE) {
			// return the pkt to host (port already set)
			// standard_metadata fields have been preserved
			// macAddr_t tempMac;
   //          tempMac = hdr.ethernet.srcAddr;
   //          hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
   //          hdr.ethernet.dstAddr = tempMac;

   //          ip4Addr_t tempip4;
   //          tempip4 = hdr.ipv4.srcAddr;
   //          hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
   //          hdr.ipv4.dstAddr = tempip4;

   //          bit<16> tempPort;
   //          tempPort = hdr.udp.srcPort;
   //          hdr.udp.srcPort = hdr.udp.dstPort;
   //          hdr.udp.dstPort = tempPort;
		}
		else {
			clone3(CloneType.E2E, E2E_CLONE_SESSION_ID, {standard_metadata}); // clone the pkt
			if (standard_metadata.enq_qdepth >= ECN_THRESHOLD) // Mark for ECN
				mark_ecn();
		}		
		
	} 
}

V1Switch(c_parser(), vrfy(), ingress(), egress(), updt(), c_deparser()) main;

