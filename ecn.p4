#include <core.p4>
#include <v1model.p4>
#include "headers.p4"
#include "parser.p4"

typedef bit<9>  egressSpec_t;

const bit<19> ECN_THRESHOLD = 10;

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
control egress(inout headers h, inout metadata meta, inout standard_metadata_t standard_metadata) { 
	action mark_ecn() {
		hdr.ipv4.ecn = 3;
	}

	apply {
		if (standard_metadata.enq_qdepth >= ECN_THRESHOLD)
			mark_ecn();
	} 
}

V1Switch(c_parser(), vrfy(), ingress(), egress(), updt(), c_deparser()) main;

