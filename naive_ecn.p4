#include <core.p4>
#include <v1model.p4>
#include "headers.p4"
#include "parser.p4"

typedef bit<9>  egressSpec_t;

const bit<19> ECN_THRESHOLD = 3;
const bit<32> E2E_CLONE_SESSION_ID_H1 = 500;
const bit<32> E2E_CLONE_SESSION_ID_H2 = 450;
const bit<32> E2E_CLONE_SESSION_ID_H3 = 400;
const bit<32> E2E_CLONE_SESSION_ID_H4 = 300;
const bit<32> QD_THRESHOLD = 20; // us
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
		// put pkt on destined egress port
		if (hdr.ipv4.isValid())
			ipv4_fwd.apply();		
	}

}


// No checksum verification
control vrfy(inout headers h, inout metadata meta) { apply {} }

// No checksum update
control updt(inout headers h, inout metadata meta) { apply {} }

// No per-port specific modification in egress
control egress(inout headers hdr, inout metadata meta, inout standard_metadata_t standard_metadata) { 
	
	action no_op() {}

	action mark_ecn() {
		hdr.ipv4.ecn = 3;
		hdr.ipv4.diffserv = (bit<6>)standard_metadata.enq_qdepth; // Queue length at enqueue
		// Not using queueing delay yet
	}

	action clone_h1() {
		clone3(CloneType.E2E, E2E_CLONE_SESSION_ID_H1, {standard_metadata}); // clone the pkt
	}

	action clone_h2() {
		clone3(CloneType.E2E, E2E_CLONE_SESSION_ID_H2, {standard_metadata}); // clone the pkt
	}

	action clone_h3() {
		clone3(CloneType.E2E, E2E_CLONE_SESSION_ID_H3, {standard_metadata}); // clone the pkt
	}

	action clone_h4() {
		clone3(CloneType.E2E, E2E_CLONE_SESSION_ID_H4, {standard_metadata}); // clone the pkt
	}

	table hclone {
		key = { 
			hdr.ipv4.srcAddr : exact; 
		}
		actions = { 
			clone_h1; 
			clone_h2; 
			clone_h3; 
			clone_h4; 
		}
	}

	


	apply {
		// Cloned pkt
		if (standard_metadata.instance_type == BMV2_V1MODEL_INSTANCE_TYPE_EGRESS_CLONE) {
			// return the pkt to host (port already set)
			// standard_metadata fields have been preserved
			macAddr_t tempMac;
            tempMac = hdr.ethernet.srcAddr;
            hdr.ethernet.srcAddr = hdr.ethernet.dstAddr;
            hdr.ethernet.dstAddr = tempMac;

            ip4Addr_t tempip4;
            tempip4 = hdr.ipv4.srcAddr;
            hdr.ipv4.srcAddr = hdr.ipv4.dstAddr;
            hdr.ipv4.dstAddr = tempip4;

            bit<16> tempPort;
            tempPort = hdr.udp.srcPort;
            hdr.udp.srcPort = hdr.udp.dstPort;
            hdr.udp.dstPort = tempPort;

            // hdr.udp.checksum = (bit<16>)standard_metadata.deq_timedelta;
		}
		else if (hdr.debug.isValid()) { // No if-else nesting more than two levels
			
			if (standard_metadata.deq_qdepth >= ECN_THRESHOLD) { // threshold on egress queue since egress proessing is more comp. intensive
				
				hclone.apply();
				
				// Mark for ECN
				mark_ecn();

			}

			hdr.debug.ws = (bit<32>)standard_metadata.enq_qdepth;
			hdr.debug.min1 = (bit<32>)standard_metadata.deq_qdepth;
		}		
		
	} 
}	

V1Switch(c_parser(), vrfy(), ingress(), egress(), updt(), c_deparser()) main;

// Debug configs

// hdr.debug.ws = meta.ws;
// hdr.debug.egr_ts = departure;
// hdr.debug.dep = standard_metadata.enq_timestamp + standard_metadata.deq_timedelta;	