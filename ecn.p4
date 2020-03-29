#include <core.p4>
#include <v1model.p4>
#include "headers.p4"
#include "parser.p4"

#define BUCKET_SIZE 4
#define CELL_SIZE 32
// power of 2 for now
#define NUM_SNAPSHOTS 2
#define LOG_NUM_SNAPSHOTS 2
#define T 16
#define LOG_T 4

#define COMPUTE(num) compute##num() 

typedef bit<9>  egressSpec_t;

const bit<19> ECN_THRESHOLD = 5;
const bit<32> E2E_CLONE_SESSION_ID = 500;
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
	
	register<bit<CELL_SIZE>>(BUCKET_SIZE) reg11;
	register<bit<CELL_SIZE>>(BUCKET_SIZE) reg12;
	register<bit<CELL_SIZE>>(BUCKET_SIZE) reg13;
	register<bit<CELL_SIZE>>(BUCKET_SIZE) reg14;

	register<bit<CELL_SIZE>>(BUCKET_SIZE) reg21;
	register<bit<CELL_SIZE>>(BUCKET_SIZE) reg22;
	register<bit<CELL_SIZE>>(BUCKET_SIZE) reg23;
	register<bit<CELL_SIZE>>(BUCKET_SIZE) reg24;

	// register<bit<CELL_SIZE>>(BUCKET_SIZE) reg31;
	// register<bit<CELL_SIZE>>(BUCKET_SIZE) reg32;
	// register<bit<CELL_SIZE>>(BUCKET_SIZE) reg33;
	// register<bit<CELL_SIZE>>(BUCKET_SIZE) reg34;

	// register<bit<CELL_SIZE>>(BUCKET_SIZE) reg41;
	// register<bit<CELL_SIZE>>(BUCKET_SIZE) reg42;
	// register<bit<CELL_SIZE>>(BUCKET_SIZE) reg43;
	// register<bit<CELL_SIZE>>(BUCKET_SIZE) reg44;

	action mark_ecn() {
		hdr.ipv4.ecn = 3;
		hdr.ipv4.diffserv = (bit<6>)standard_metadata.enq_qdepth; // Queue length at enqueue
		// Not using queueing delay yet
	}

	action compute1() {
		hash<bit<32>, bit<32>, tuple<bit<32>, bit<32>, bit<16>, bit<16>, bit<8>>, bit<32>>(meta.idx1, HashAlgorithm.crc32_custom, 32w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol }, BUCKET_SIZE);
		reg11.read(meta.val1, meta.idx1);
		meta.val1 = meta.val1 + 1;
		reg11.write(meta.idx1, meta.val1);

		hash<bit<32>, bit<32>, tuple<bit<32>, bit<32>, bit<16>, bit<16>, bit<8>>, bit<32>>(meta.idx2, HashAlgorithm.crc32_custom, 32w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol }, BUCKET_SIZE);
		reg12.read(meta.val2, meta.idx2);
		meta.val2 = meta.val2 + 1;
		reg12.write(meta.idx2, meta.val2);
		
		hash<bit<32>, bit<32>, tuple<bit<32>, bit<32>, bit<16>, bit<16>, bit<8>>, bit<32>>(meta.idx3, HashAlgorithm.crc32_custom, 32w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol }, BUCKET_SIZE);
		reg13.read(meta.val3, meta.idx3);
		meta.val3 = meta.val3 + 1;
		reg13.write(meta.idx3, meta.val3);
		
		hash<bit<32>, bit<32>, tuple<bit<32>, bit<32>, bit<16>, bit<16>, bit<8>>, bit<32>>(meta.idx4, HashAlgorithm.crc32_custom, 32w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol }, BUCKET_SIZE);
		reg14.read(meta.val4, meta.idx4);
		meta.val4 = meta.val4 + 1;
		reg14.write(meta.idx4, meta.val4);
	}

	action compute2() {
		hash<bit<32>, bit<32>, tuple<bit<32>, bit<32>, bit<16>, bit<16>, bit<8>>, bit<32>>(meta.idx1, HashAlgorithm.crc32_custom, 32w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol }, BUCKET_SIZE);
		reg21.read(meta.val1, meta.idx1);
		meta.val1 = meta.val1 + 1;
		reg21.write(meta.idx1, meta.val1);

		hash<bit<32>, bit<32>, tuple<bit<32>, bit<32>, bit<16>, bit<16>, bit<8>>, bit<32>>(meta.idx2, HashAlgorithm.crc32_custom, 32w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol }, BUCKET_SIZE);
		reg22.read(meta.val2, meta.idx2);
		meta.val2 = meta.val2 + 1;
		reg22.write(meta.idx2, meta.val2);

		hash<bit<32>, bit<32>, tuple<bit<32>, bit<32>, bit<16>, bit<16>, bit<8>>, bit<32>>(meta.idx3, HashAlgorithm.crc32_custom, 32w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol }, BUCKET_SIZE);
		reg23.read(meta.val3, meta.idx3);
		meta.val3 = meta.val3 + 1;
		reg23.write(meta.idx3, meta.val3);

		hash<bit<32>, bit<32>, tuple<bit<32>, bit<32>, bit<16>, bit<16>, bit<8>>, bit<32>>(meta.idx4, HashAlgorithm.crc32_custom, 32w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol }, BUCKET_SIZE);
		reg24.read(meta.val4, meta.idx4);
		meta.val4 = meta.val4 + 1;
		reg24.write(meta.idx4, meta.val4);
	}

	// action compute31() {
	// 	hash<bit<32>, bit<32>, tuple<bit<32>, bit<32>, bit<16>, bit<16>, bit<8>>, bit<32>>(meta.idx1, HashAlgorithm.crc32_custom, 32w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol }, BUCKET_SIZE);
	// 	reg31.read(meta.val1, meta.idx1);
	// 	meta.val1 = meta.val1 + 1;
	// 	reg31.write(meta.idx1, meta.val1);
	// }

	// action compute32() {
	// 	hash<bit<32>, bit<32>, tuple<bit<32>, bit<32>, bit<16>, bit<16>, bit<8>>, bit<32>>(meta.idx2, HashAlgorithm.crc32_custom, 32w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol }, BUCKET_SIZE);
	// 	reg32.read(meta.val2, meta.idx2);
	// 	meta.val2 = meta.val2 + 1;
	// 	reg32.write(meta.idx2, meta.val2);
	// }

	// action compute33() {
	// 	hash<bit<32>, bit<32>, tuple<bit<32>, bit<32>, bit<16>, bit<16>, bit<8>>, bit<32>>(meta.idx3, HashAlgorithm.crc32_custom, 32w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol }, BUCKET_SIZE);
	// 	reg33.read(meta.val3, meta.idx3);
	// 	meta.val3 = meta.val3 + 1;
	// 	reg33.write(meta.idx3, meta.val3);
	// }

	// action compute34() {
	// 	hash<bit<32>, bit<32>, tuple<bit<32>, bit<32>, bit<16>, bit<16>, bit<8>>, bit<32>>(meta.idx4, HashAlgorithm.crc32_custom, 32w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol }, BUCKET_SIZE);
	// 	reg34.read(meta.val4, meta.idx4);
	// 	meta.val4 = meta.val4 + 1;
	// 	reg34.write(meta.idx4, meta.val4);
	// }

	// action compute41() {
	// 	hash<bit<32>, bit<32>, tuple<bit<32>, bit<32>, bit<16>, bit<16>, bit<8>>, bit<32>>(meta.idx1, HashAlgorithm.crc32_custom, 32w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol }, BUCKET_SIZE);
	// 	reg41.read(meta.val1, meta.idx1);
	// 	meta.val1 = meta.val1 + 1;
	// 	reg41.write(meta.idx1, meta.val1);
	// }

	// action compute42() {
	// 	hash<bit<32>, bit<32>, tuple<bit<32>, bit<32>, bit<16>, bit<16>, bit<8>>, bit<32>>(meta.idx2, HashAlgorithm.crc32_custom, 32w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol }, BUCKET_SIZE);
	// 	reg42.read(meta.val2, meta.idx2);
	// 	meta.val2 = meta.val2 + 1;
	// 	reg42.write(meta.idx2, meta.val2);
	// }

	// action compute43() {
	// 	hash<bit<32>, bit<32>, tuple<bit<32>, bit<32>, bit<16>, bit<16>, bit<8>>, bit<32>>(meta.idx3, HashAlgorithm.crc32_custom, 32w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol }, BUCKET_SIZE);
	// 	reg43.read(meta.val3, meta.idx3);
	// 	meta.val3 = meta.val3 + 1;
	// 	reg43.write(meta.idx3, meta.val3);
	// }

	// action compute44() {
	// 	hash<bit<32>, bit<32>, tuple<bit<32>, bit<32>, bit<16>, bit<16>, bit<8>>, bit<32>>(meta.idx4, HashAlgorithm.crc32_custom, 32w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol }, BUCKET_SIZE);
	// 	reg44.read(meta.val4, meta.idx4);
	// 	meta.val4 = meta.val4 + 1;
	// 	reg44.write(meta.idx4, meta.val4);
	// }

	// Owing to recycled snapshots 
	

	action read1() {
		hash<bit<32>, bit<32>, tuple<bit<32>, bit<32>, bit<16>, bit<16>, bit<8>>, bit<32>>(meta.idx1, HashAlgorithm.crc32_custom, 32w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol }, BUCKET_SIZE);
		hash<bit<32>, bit<32>, tuple<bit<32>, bit<32>, bit<16>, bit<16>, bit<8>>, bit<32>>(meta.idx2, HashAlgorithm.crc32_custom, 32w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol }, BUCKET_SIZE);
		hash<bit<32>, bit<32>, tuple<bit<32>, bit<32>, bit<16>, bit<16>, bit<8>>, bit<32>>(meta.idx3, HashAlgorithm.crc32_custom, 32w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol }, BUCKET_SIZE);
		hash<bit<32>, bit<32>, tuple<bit<32>, bit<32>, bit<16>, bit<16>, bit<8>>, bit<32>>(meta.idx4, HashAlgorithm.crc32_custom, 32w0, { hdr.ipv4.srcAddr, hdr.ipv4.dstAddr, hdr.udp.srcPort, hdr.udp.dstPort, hdr.ipv4.protocol }, BUCKET_SIZE);
		reg11.read(meta.val1, meta.idx1);
		reg12.read(meta.val2, meta.idx2);
		reg13.read(meta.val3, meta.idx3);
		reg14.read(meta.val4, meta.idx4);
		}

	table invoke {
		key = {
			meta.ws : exact;
		}
		actions = {
			COMPUTE(1);
			COMPUTE(2);
			// lookup3;
			// lookup4;
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

            hdr.udp.checksum = (bit<16>)standard_metadata.deq_timedelta;
		}
		else if (hdr.udp.isValid() && hdr.udp.srcPort == 12345) { // No if-else nesting more than two levels
			
			clone3(CloneType.E2E, E2E_CLONE_SESSION_ID, {standard_metadata}); // clone the pkt
			
			if (standard_metadata.enq_qdepth >= ECN_THRESHOLD) {
				// Mark for ECN
				mark_ecn();
				// if (standard_metadata.deq_timedelta >= QD_THRESHOLD) {
				// 	// id as contributing flow
				// 	bit<32> arrival = standard_metadata.enq_timestamp;
				// 	bit<32> departure = (bit<32>)standard_metadata.egress_global_timestamp;
					
				// 	// identify writing snapshot and hash into it
				// 	meta.ws = (departure >> LOG_T) & LOG_NUM_SNAPSHOTS;
				// 	invoke.apply();									
					
				// }
			}
		}		
		
	} 
}

V1Switch(c_parser(), vrfy(), ingress(), egress(), updt(), c_deparser()) main;

