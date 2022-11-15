/* -*- P4_16 -*- */

#include <core.p4>
#include <tna.p4>


/*************************************************************************
 ************* C O N S T A N T S    A N D   T Y P E S  *******************
**************************************************************************/
#define PAYLOAD_LEN hdr.ipv4.total_len - 20
#define MAX_FLOW 1 << 16
#define MAX_PKT_LEN_INTERVAL 1 << 10
#define PKTS_PER_BATCH 32768
#define HALF_OPEN_CONNECTIONS_LIMIT 5
#define FLOW_EXPIRE_TIME_INTERVAL 1000000


typedef bit<48> mac_addr_t;
typedef bit<32> ipv4_addr_t;
typedef bit<16> ether_type_t;

typedef bit<4> header_type_t; 
typedef bit<4> header_info_t;

const ether_type_t ETHERTYPE_IPV4 = 16w0x0800;
const ether_type_t ETHERTYPE_VLAN = 16w0x0810;
const ether_type_t ETHERTYPE_BRIDGE = 16w0x8937;

const header_type_t HEADER_TYPE_BRIDGE         = 0xB;
const header_type_t HEADER_TYPE_MIRROR_INGRESS = 0xC;
const header_type_t HEADER_TYPE_MIRROR_EGRESS  = 0xD;
const header_type_t HEADER_TYPE_RESUBMIT       = 0xA;

const PortId_t RECIRCULATE_PORT = 68;

// digest
const bit<3> MATCH_SUCCESS = 1;
const bit<3> COMPLETION_EXPIRE = 2;

const bit<4> UNCOMPLETED_FLOW_EXPIRE = 1;

enum bit<16> application_type_t {
    QQ               = 0x0001,
    TEAMVIEWER       = 0x0002
}

// struct for digest header
struct match_digest_t {
    bit<32> client;
    bit<32> server;
    bit<16> client_port;
    bit<16> server_port;
    bit<8>  proto;
}

struct expire_digest_t {
    bit<16> flow_id;
}

#define INTERNAL_HEADER         \
    header_type_t header_type;  \
    header_info_t header_info

header inthdr_h {
    INTERNAL_HEADER;
}

/* Bridged metadata */
header bridge_h {
    INTERNAL_HEADER;
    // bridged data
    bit<16>          current_state;          // without 0
}

/*************************************************************************
 ***********************  H E A D E R S  *********************************
 *************************************************************************/

/*  Define all the headers the program will recognize             */
/*  The actual sets of headers processed by each gress can differ */

header pkt_gen_h {
    bit<8>                      is_recirculate;
    bit<8>                      recirculate_times;
    bit<8>                      recirculate_upper_limit;
}

/* Standard ethernet header */
header ethernet_h {
    bit<48>   dst_addr;
    bit<48>   src_addr;
    bit<16>   ether_type;
}

header vlan_tag_h {
    bit<3>   pcp;
    bit<1>   cfi;
    bit<12>  vid;
    bit<16>  ether_type;
}

header ipv4_h {
    bit<4>   version;
    bit<4>   ihl;
    bit<8>   diffserv;
    bit<16>  total_len;
    bit<16>  identification;
    bit<3>   flags;
    bit<13>  frag_offset;
    bit<8>   ttl;
    bit<8>   protocol;
    bit<16>  hdr_checksum;
    bit<32>  src_addr;
    bit<32>  dst_addr;
}

header udp_h {
    bit<16>  src_port;
    bit<16>  dst_port;
    bit<16>  len;
    bit<16>  checksum;
}

header tcp_h {
    bit<16>  src_port;
    bit<16>  dst_port;
    bit<32>  seq_no;
    bit<32>  ack_no;
    bit<4>   data_offset;
    bit<4>   res;
    bit<8>   flags;
    bit<16>  window;
    bit<16>  checksum;
    bit<16>  urgent_ptr;
}

header tcp_options_t {
    varbit<320> data;
}

header first_4byte_payload_h {
    // bit<8>   data0;
    // bit<8>   data1;
    // bit<8>   data2;
    // bit<8>   data3;
    bit<32>     data;
}



/*************************************************************************
 **************  I N G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/
 
    /***********************  H E A D E R S  ************************/

struct my_ingress_headers_t {
    pktgen_timer_header_t       pkt_gen;
    ethernet_h                  ethernet;
    bridge_h                    bridge;
    ipv4_h                      ipv4;
    udp_h                       udp;
    tcp_h                       tcp;
    tcp_options_t               tcp_option;
    first_4byte_payload_h       payload;
}

    /******  G L O B A L   I N G R E S S   M E T A D A T A  *********/

struct my_ingress_metadata_t {
    bit<32>         address;
    bit<16>         tcp_port;
    bit<16>         udp_port;

    bit<16>         flow_id;   
    // srcIP + dstIP
    bit<16>         IP_id;

    bit<8>          flow_direction;         
    bit<16>         payload_length;
    
    // dir1 info
    bit<32>         client_payload;
    bit<16>         client_length;
    bit<16>         client_port;
    bit<16>         server_port;

    bit<16>         current_state;          // init 0
    bit<16>         single_dir_flow_res;
    bit<8>          single_flow_flag;


    // pkt_len_verify
    bit<10>         dir1_interval_verify_index;
    bit<10>         dir2_interval_verify_index;

    bit<2>          dir1_pkt_len_left_verify_res;   // init 1
    bit<2>          dir1_pkt_len_right_verify_res;  // init 1

    bit<2>          dir2_pkt_len_left_verify_res;   // init 1
    bit<2>          dir2_pkt_len_right_verify_res;  // init 1

    bit<2>          matching_state;     // 0: none, 1:matching, 2:success(after payload verify)

    bit<16>         application_ident_result;


    // flow expire
    bit<4>          flow_flag;      // 0: no flow, 1: only see dir1, 2: dir1+dir2
    bit<4>          uncompleted_flow_expire_flag;
    // half-open
    bit<8>          half_open_connection_flag;
}

    /***********************  P A R S E R  **************************/
parser IngressParser(packet_in        pkt,
    /* User */    
    out my_ingress_headers_t          hdr,
    out my_ingress_metadata_t         metadata,
    /* Intrinsic */
    out ingress_intrinsic_metadata_t  ig_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
     state start {
        pkt.extract(ig_intr_md);
        pkt.advance(PORT_METADATA_SIZE);
        transition init_meta;
    }

    state init_meta {
        metadata = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 1, 1, 0, 0, 0, 0, 0};        // pkt_len_verify_res init -> 1

        transition parse_intermediate;
    }

    state parse_intermediate {
        transition select(ig_intr_md.ingress_port) {
            68              :   parse_pkt_gen;
            default: parse_ethernet;
        }
    }

    state parse_pkt_gen {
        pkt.extract(hdr.pkt_gen);
        // pkt gen generate ipv4+udp packet
        transition parse_ethernet;
    }

    state parse_ethernet {
        pkt.extract(hdr.ethernet);
        transition select(hdr.ethernet.ether_type) {
            ETHERTYPE_IPV4:     parse_ipv4;
            ETHERTYPE_BRIDGE:   parse_bridge;
            default: accept;
        }
    }

    state parse_bridge {
        pkt.extract(hdr.bridge);
        transition parse_ipv4;
    }

    state parse_ipv4 {
        pkt.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol) {
            17     : parse_udp;
            6      : parse_tcp;
            default: accept;
        }
    }

    state parse_udp {
        pkt.extract(hdr.udp);
        transition parse_4byte_payload;
    }

    state parse_tcp {
        pkt.extract(hdr.tcp);
        transition parse_tcp_option;
    }

    state parse_tcp_option {
        // parse tcp option
        pkt.extract(
            hdr.tcp_option, 
            ((bit<32>)hdr.tcp.data_offset - 5) * 32w32);        // 
        transition parse_4byte_payload;
    }

    state parse_4byte_payload {
        pkt.extract(hdr.payload);
        transition accept;
    }
}

    /***************** M A T C H - A C T I O N  *********************/

control Ingress(
    /* User */
    inout my_ingress_headers_t                       hdr,
    inout my_ingress_metadata_t                      metadata,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_t               ig_intr_md,
    in    ingress_intrinsic_metadata_from_parser_t   ig_prsr_md,
    inout ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md,
    inout ingress_intrinsic_metadata_for_tm_t        ig_tm_md)
{

/* ********************** ACTION ********************** */
    action ai_set_egress_port(bit<9> port) {
        ig_tm_md.ucast_egress_port = port;
    }

    action ai_nop() {
    }

/* ********************** FLOW EXPIRE ********************** */
    Register<bit<32>, _>(size=MAX_FLOW, initial_value=0) uncompleted_flow_time;
    RegisterAction<bit<32>, _, void>(uncompleted_flow_time)
    uncompleted_flow_record_time = {
        void apply(inout bit<32> time) {
            time = ig_prsr_md.global_tstamp[41:10];
        }
    };

    RegisterAction<bit<32>, _, bit<4>>(uncompleted_flow_time)
    uncompleted_flow_expire_check = {
        void apply(inout bit<32> time, out bit<4> res) {
            if(ig_prsr_md.global_tstamp[41:10] - time > FLOW_EXPIRE_TIME_INTERVAL) {
                res = UNCOMPLETED_FLOW_EXPIRE;
            } else {
                res = 0;
            }
        }
    };



    action ai_uncompleted_flow_record_time() {
        uncompleted_flow_record_time.execute(metadata.flow_id);
    }

    // uncompleted flow update time
    @stage(3)
    table ti_uncompleted_flow_record_time {
        actions = {ai_uncompleted_flow_record_time;}
        size = 1;
        const default_action = ai_uncompleted_flow_record_time();
    }

    action ai_uncompleted_flow_expire() {
        metadata.uncompleted_flow_expire_flag = uncompleted_flow_expire_check.execute(metadata.flow_id);
    }

    // uncompleted flow expire, stage1 to ompflow id
    @stage(3)
    table ti_uncompleted_flow_expire {
        key = {
            hdr.pkt_gen.isValid()   :   exact;
        }
        actions = {ai_uncompleted_flow_expire;}
        size = 1;
        const entries = {
            (true)  :   ai_uncompleted_flow_expire();
        }
    }


    
    Register<bit<8>, _>(size=MAX_FLOW, initial_value=0) flow_flag;
    RegisterAction<bit<8>, _, bit<8>>(flow_flag)
    set_dir1_flag = {
        void apply(inout bit<8> flag, out bit<8> res) {
            if(flag == 0) {
                flag = 1;
                res = 0;
            } else {
                res = 3;
            }
        }
    };
    RegisterAction<bit<8>, _, bit<8>>(flow_flag)
    set_dir2_flag = {
        void apply(inout bit<8> flag, out bit<8> res) {
            if(flag == 1) {
                flag = 2;
                res = 1;
            } else {
                res = 3;
            }
            
        }
    };
    RegisterAction<bit<8>, _, void>(flow_flag)
    clear_flag = {
        void apply(inout bit<8> flag) {
            flag = 0;
        }
    };

    action ai_set_dir1_flow_flag() {
        metadata.flow_flag = (bit<4>)set_dir1_flag.execute(metadata.flow_id);
    }
    action ai_set_dir2_flow_flag() {
        metadata.flow_flag = (bit<4>)set_dir2_flag.execute(metadata.flow_id);
    }

    
    @stage(4)
    table ti_set_flow_flag {
        key = {
            metadata.flow_direction     :   exact;
        }
        actions = {ai_set_dir1_flow_flag; ai_set_dir2_flow_flag;}
        size = 2;
        const entries = {
            (1)     :       ai_set_dir1_flow_flag();
            (2)     :       ai_set_dir2_flow_flag();
        }
    }

    action ai_clear_flow_flag() {
        clear_flag.execute(metadata.flow_id);
    }

    @stage(4)
    table ti_clear_flow_flag {
        key = {
            hdr.pkt_gen.isValid()                   :   exact;
            metadata.uncompleted_flow_expire_flag   :   exact;
        }
        actions = {ai_clear_flow_flag;}
        size = 1;
        const entries = {
            (true, UNCOMPLETED_FLOW_EXPIRE) :   ai_clear_flow_flag();
        }
    }


   
    Register<bit<32>, _>(size=MAX_FLOW, initial_value=0) completion_list_time;
    RegisterAction<bit<32>, _, void>(completion_list_time)
    update_time = {
        void apply(inout bit<32> time) {
            time = ig_prsr_md.global_tstamp[41:10];
        }
    };

    RegisterAction<bit<32>, _, bit<3>>(completion_list_time)
    get_time_cmp_res = {
        void apply(inout bit<32> time, out bit<3> res) {
            if(ig_prsr_md.global_tstamp[41:10] - time > FLOW_EXPIRE_TIME_INTERVAL) {
                res = COMPLETION_EXPIRE;
            } else {
                res = 0;
            }
        }
    };

    action ai_tcp_completion_list(bit<16> list_index) {
        update_time.execute(list_index);
    }

    action ai_udp_completion_list(bit<16> list_index) {
        update_time.execute(list_index);
    }


    // tcp completion list
    @stage(1)
    table ti_tcp_completion_list {
        key = {
            hdr.tcp.isValid()   :   exact;
            hdr.ipv4.src_addr   :   exact;
            hdr.ipv4.dst_addr   :   exact;
            hdr.tcp.src_port    :   exact;
            hdr.tcp.dst_port    :   exact;
        }
        actions = {ai_tcp_completion_list;}
        size = 256;
    }

    // udp completion list
    @stage(1)
    table ti_udp_completion_list {
        key = {
            hdr.udp.isValid()   :   exact;
            hdr.ipv4.src_addr   :   exact;
            hdr.ipv4.dst_addr   :   exact;
            hdr.udp.src_port    :   exact;
            hdr.udp.dst_port    :   exact;
        }
        actions = {ai_udp_completion_list;}
        size = 256;
    }

    // expire completed flow
    action ai_expire_completed_list() {
        ig_dprsr_md.digest_type = get_time_cmp_res.execute(metadata.flow_id);
    }

    @stage(1)
    table ti_expire_completed_list {
        key = {
            hdr.pkt_gen.isValid()   :   exact;
        }
        actions = {ai_expire_completed_list;}
        size = 1;
        const entries = {
            (true)  :   ai_expire_completed_list();
        }
    }

/* ********************** HALF-OPEN CONNECTION TABLE ********************** */
    // hash algorithm
    Hash<bit<16>>(HashAlgorithm_t.CRC16) hash_algo_src_IP;
    Hash<bit<16>>(HashAlgorithm_t.CRC16) hash_algo_dst_IP;

    action ai_get_srcIP_id() {
        metadata.IP_id = (bit<16>)hash_algo_src_IP.get({
                hdr.ipv4.src_addr
            });
    }
    action ai_get_dstIP_id() {
        metadata.IP_id = (bit<16>)hash_algo_dst_IP.get({
                hdr.ipv4.dst_addr
            });
    }

    @stage(4)
    table ti_get_IP_id {
        key = {
            metadata.flow_direction     :   exact;
        }
        actions = {ai_get_srcIP_id; ai_get_dstIP_id;}
        size = 2;
        const entries = {
            (1)      :       ai_get_srcIP_id();
            (2)      :       ai_get_dstIP_id();
        }
        // const default_action = ai_get_flow_id();
    }


    Register<bit<8>, _>(size=MAX_FLOW, initial_value=0) half_open_connections;
    RegisterAction<bit<8>, _, bit<8>>(half_open_connections)
    inc_connections = {
        void apply(inout bit<8> connections, out bit<8> res) {
            
            if(connections >= HALF_OPEN_CONNECTIONS_LIMIT) {
                res = 1;
            } else {
                connections = connections + 1;
                res = 0;
            }
        }
    };

    RegisterAction<bit<8>, _, bit<8>>(half_open_connections)
    sub_connections = {
        void apply(inout bit<8> connections, out bit<8> res) {
            connections = connections - 1;
            if(connections >= HALF_OPEN_CONNECTIONS_LIMIT) {
                res = 1;
            } else {
                res = 0;
            }
        }
    };

    action ai_inc_half_open_connections() {
        metadata.half_open_connection_flag = inc_connections.execute(metadata.IP_id);
    }

    action ai_sub_half_open_connections() {
        metadata.half_open_connection_flag = sub_connections.execute(metadata.IP_id);
    }

    @stage(5)
    table ti_half_open_connections {
        key = {
            metadata.flow_direction     :   exact;
            metadata.flow_flag          :   exact;
        }
        actions = {ai_inc_half_open_connections; ai_sub_half_open_connections;}
        size = 2;
        const entries = {
            (1, 0)      :       ai_inc_half_open_connections();
            (2, 1)      :       ai_sub_half_open_connections();
        }
    }






/* ********************** PKT_GEN ********************** */

    action ai_set_pkt_gen_flow_id_with_batch0() {
        metadata.flow_id = hdr.pkt_gen.packet_id;
        // debug
        // hdr.udp.dst_port = hdr.pkt_gen.batch_id;
        // hdr.udp.src_port = hdr.pkt_gen.packet_id;
    }

    action ai_set_pkt_gen_flow_id_with_batch1(bit<16> offset) {
        metadata.flow_id = hdr.pkt_gen.packet_id + offset;
        // debug
        // hdr.udp.dst_port = hdr.pkt_gen.batch_id;
        // hdr.udp.src_port = hdr.pkt_gen.packet_id;
    }

    
    // batch: 0..1, packet_id: 0.. 2^16 / 2 - 1
    @stage(0)
    table ti_set_pkt_gen_flow_id {
        key = {
            hdr.pkt_gen.isValid()       :       exact;
            hdr.pkt_gen.batch_id        :       exact;
        }
        actions = {ai_set_pkt_gen_flow_id_with_batch0; ai_set_pkt_gen_flow_id_with_batch1;}
        size = 2;
        const entries = {
            (true, 0)   :   ai_set_pkt_gen_flow_id_with_batch0();
            (true, 1)   :   ai_set_pkt_gen_flow_id_with_batch1(PKTS_PER_BATCH);
        }
    }





/* ********************** TABLE ********************** */
  
    // init metadata.address
    action ai_init_metadata() {
        metadata.address = hdr.ipv4.src_addr ^ hdr.ipv4.dst_addr;
    }
    
    @stage(1)
    table ti_init_metadata {
        actions = {ai_init_metadata;}
        size = 1;
        const default_action = ai_init_metadata();
    }

    action ai_xor_port_tcp() {
        metadata.tcp_port = hdr.tcp.src_port ^ hdr.tcp.dst_port;
    }

    action ai_xor_port_udp() {
        metadata.udp_port = hdr.udp.src_port ^ hdr.udp.dst_port;
    }

    @stage(1)
    table ti_xor_port {
        key = {
            hdr.tcp.isValid()   :   exact;
        }
        actions = {ai_xor_port_tcp; ai_xor_port_udp; NoAction;}
        size = 2;
        const entries = {
            (true)       :       ai_xor_port_tcp();
            (false)      :       ai_xor_port_udp();
        }
        const default_action = NoAction();
    }

    // get payload_length
    action ai_get_udp_payload_length() {
        metadata.payload_length = hdr.udp.len - 8;      // 
    }

    @stage(2)
    table ti_get_udp_payload_length {
        key = {
            hdr.udp.isValid()   :   exact;
        }
        actions = {ai_get_udp_payload_length; ai_nop;}
        size = 1;
        const entries = {
            (true)      :       ai_get_udp_payload_length();
        }
        const default_action = ai_nop();
    }

    action ai_get_tcp_hdr_length(bit<16> tcp_and_payload_length) {
        metadata.payload_length = tcp_and_payload_length;
    }
    
    @stage(2)
    table ti_get_tcp_hdr_length {
        key = {
            hdr.tcp.isValid()       :   exact;
            hdr.tcp.data_offset     :   exact;
        }
        actions = {ai_get_tcp_hdr_length; NoAction;}
        size = 16;
        const default_action = NoAction();
    }

    action ai_get_tcp_payload_length() {
        metadata.payload_length = hdr.ipv4.total_len - metadata.payload_length;
    }

    
    @stage(3)
    table ti_get_tcp_payload_length {
        key = {
            hdr.tcp.isValid()       :   exact;
        }
        actions = {ai_get_tcp_payload_length; NoAction;}
        size = 1;
        // const default_action = NoAction();
        const entries = {
            (true)  :   ai_get_tcp_payload_length();
        }
    }


    // hash algorithm
    Hash<bit<16>>(HashAlgorithm_t.CRC32) hash_algo_tcp;
    Hash<bit<16>>(HashAlgorithm_t.CRC32) hash_algo_udp;

    action ai_get_flow_id_tcp() {
        metadata.flow_id = (bit<16>)hash_algo_tcp.get({
                metadata.address,  // get same hash for different direction
                metadata.tcp_port,
                hdr.ipv4.protocol
            });
    }
    action ai_get_flow_id_udp() {
        metadata.flow_id = (bit<16>)hash_algo_udp.get({
                metadata.address,  // get same hash for different direction
                metadata.udp_port,
                hdr.ipv4.protocol
            });
    }

    @stage(2)
    table ti_get_flow_id {
        key = {
            hdr.tcp.isValid()   :   exact;
        }
        actions = {ai_get_flow_id_tcp; ai_get_flow_id_udp;}
        size = 2;
        const entries = {
            (true)      :       ai_get_flow_id_tcp();
            (false)     :       ai_get_flow_id_udp();
        }
        // const default_action = ai_get_flow_id();
    }
    
    // packet direction 
    Register<bit<32>, bit<16>>(size=MAX_FLOW, initial_value=0) flow_direction;
    RegisterAction<bit<32>, _, bit<8>>(flow_direction)
    get_direction = {
        void apply(inout bit<32> peer_ip, out bit<8> direction) {
            if(hdr.ipv4.src_addr != peer_ip) {
                direction = 1;
                peer_ip = hdr.ipv4.dst_addr;
            } else {
                direction = 2;
            }
        }
    };

    action ai_get_direction() {
        // get flow direction
        metadata.flow_direction = get_direction.execute(metadata.flow_id);
    }

    @stage(3)
    table ti_get_direction {
        actions = {ai_get_direction;}
        size = 1;
        const default_action = ai_get_direction();
    }

    // get/set server port
    Register<bit<16>, bit<16>>(size=MAX_FLOW, initial_value=0) server_ports;
    RegisterAction<bit<16>, _, void>(server_ports)
    set_server_tcp_port = {
        void apply(inout bit<16> server_port) {
            server_port = hdr.tcp.dst_port;
        }
    };

    RegisterAction<bit<16>, _, void>(server_ports)
    set_server_udp_port = {
        void apply(inout bit<16> server_port) {
            server_port = hdr.udp.dst_port;
        }
    };

    RegisterAction<bit<16>, _, bit<16>>(server_ports)
    get_server_port = {
        void apply(inout bit<16> server_port, out bit<16> sport) {
            sport = server_port;
        }
    };

    action ai_set_tcp_port() {
        set_server_tcp_port.execute(metadata.flow_id);
        metadata.client_port = hdr.tcp.src_port;
        metadata.server_port = hdr.tcp.dst_port;
    }

    action ai_set_udp_port() {
        set_server_udp_port.execute(metadata.flow_id);
        metadata.client_port = hdr.udp.src_port;
        metadata.server_port = hdr.udp.dst_port;
    }

    action ai_get_tcp_server_port() {
        metadata.server_port = get_server_port.execute(metadata.flow_id);
        metadata.client_port = hdr.tcp.src_port;
    }

    action ai_get_udp_server_port() {
        metadata.server_port = get_server_port.execute(metadata.flow_id);
        metadata.client_port = hdr.udp.src_port;
    }

    @stage(7)
    table ti_access_server_port {
        key = {
            hdr.tcp.isValid()           :   exact;
            metadata.flow_direction     :   exact;
        }
        actions = {ai_set_tcp_port; ai_set_udp_port; ai_get_tcp_server_port; ai_get_udp_server_port;}
        size = 4;
        const entries = {
            (true,  1)     :       ai_set_tcp_port();
            (true,  2)     :       ai_get_tcp_server_port();
            (false, 1)     :       ai_set_udp_port();
            (false, 2)     :       ai_get_udp_server_port();
        }
    }

    // set/get client packet length
    Register<bit<16>, bit<16>>(size=MAX_FLOW, initial_value=0) client_lengths;
    RegisterAction<bit<16>, _, void>(client_lengths)
    set_client_length = {
        void apply(inout bit<16> client_length) {
            client_length = metadata.payload_length;
        }
    };

    RegisterAction<bit<16>, _, bit<16>>(client_lengths)
    get_client_length = {
        void apply(inout bit<16> client_length, out bit<16> clength) {
            clength = client_length;
        }
    };

    action ai_set_client_length() {
        set_client_length.execute(metadata.flow_id);
    }

    action ai_get_client_length() {
        metadata.client_length = get_client_length.execute(metadata.flow_id);
    }

    @stage(7)
    table ti_access_client_length {
        key = {
            metadata.flow_direction     :   exact;
        }
        actions = {ai_set_client_length; ai_get_client_length;}
        size = 2;
        const entries = {
            (1)     :       ai_set_client_length();
            (2)     :       ai_get_client_length();
        }
    }

    // set/get client payload
    Register<bit<32>, bit<16>>(size=MAX_FLOW, initial_value=0) client_payloads;
    RegisterAction<bit<32>, _, void>(client_payloads)
    set_client_payload = {
        void apply(inout bit<32> client_payload) {
            client_payload = hdr.payload.data;
        }
    };

    RegisterAction<bit<32>, _, bit<32>>(client_payloads)
    get_client_payload = {
        void apply(inout bit<32> client_payload, out bit<32> cpayload) {
            cpayload = client_payload;
        }
    };

    action ai_set_client_payload() {
        set_client_payload.execute(metadata.flow_id);
    }

    action ai_get_client_payload() {
        metadata.client_payload = get_client_payload.execute(metadata.flow_id);
    }

    @stage(7)
    table ti_access_client_payload {
        key = {
            metadata.flow_direction     :   exact;
            // hdr.payload.data.isValid()   :   exact;
        }
        actions = {ai_set_client_payload; ai_get_client_payload;}
        size = 2;
        const entries = {
            (1)     :       ai_set_client_payload();
            (2)     :       ai_get_client_payload();
        }
    }



    // matching process
    action ai_tcp_flow_matching(bit<10> dir1_interval_verify_index, bit<10> dir2_interval_verify_index, bit<16> application_ident_result) {
        metadata.dir1_interval_verify_index = dir1_interval_verify_index;
        metadata.dir2_interval_verify_index = dir2_interval_verify_index;
        // set the metadata for ident result
        metadata.application_ident_result = application_ident_result;
        metadata.matching_state = 1;

    }


    @stage(8)
    table ti_tcp_flow_matching {
        key = {
            metadata.flow_direction     :   exact;
            metadata.client_payload     :   ternary;
            hdr.payload.data            :   ternary;
            metadata.server_port        :   ternary;
        }
        actions = {ai_tcp_flow_matching; ai_nop;}
        size = 256;

    }

    action ai_udp_flow_matching(bit<10> dir1_interval_verify_index, bit<10> dir2_interval_verify_index, bit<16> application_ident_result) {
        metadata.dir1_interval_verify_index = dir1_interval_verify_index;
        metadata.dir2_interval_verify_index = dir2_interval_verify_index;
        // set the metadata for ident result
        metadata.application_ident_result = application_ident_result;
        metadata.matching_state = 1;

    }

    @stage(8)
    table ti_udp_flow_matching {
        key = {
            metadata.flow_direction     :   exact;
            metadata.client_payload     :   ternary;
            hdr.payload.data            :   ternary;
            metadata.server_port        :   ternary;
        }
        actions = {ai_udp_flow_matching; ai_nop;}
        size = 256;
    }

    // packet len verify
    Register<bit<16>, bit<16>>(size=MAX_PKT_LEN_INTERVAL, initial_value=0) dir1_left_interval;
    Register<bit<16>, bit<16>>(size=MAX_PKT_LEN_INTERVAL, initial_value=0) dir1_right_interval;

    RegisterAction<bit<16>, _, bit<2>>(dir1_left_interval)
    dir1_left_interval_verify = {
        void apply(inout bit<16> left_side, out bit<2> result) {
            if(metadata.client_length >= left_side) {
                result = 1;
            } else {
                result = 0;
            }
        }
    };

    RegisterAction<bit<16>, _, bit<2>>(dir1_right_interval)
    dir1_right_interval_verify = {
        void apply(inout bit<16> right_side, out bit<2> result) {
            if(metadata.client_length <= right_side) {
                result = 1;
            } else {
                result = 0;
            }
        }
    };

    action ai_dir1_pkt_len_left_verify() {
        metadata.dir1_pkt_len_left_verify_res  = dir1_left_interval_verify.execute(metadata.dir1_interval_verify_index);
    }

    // dir1 packet length interval verify 
    @stage(9)
    table ti_dir1_pkt_len_left_verify {
        actions = {ai_dir1_pkt_len_left_verify;}
        size = 1;
        const default_action = ai_dir1_pkt_len_left_verify();
    }

    action ai_dir1_pkt_len_right_verify() {
        metadata.dir1_pkt_len_right_verify_res = dir1_right_interval_verify.execute(metadata.dir1_interval_verify_index);
    }

    @stage(9)
    table ti_dir1_pkt_len_right_verify {
        actions = {ai_dir1_pkt_len_right_verify;}
        size = 1;
        const default_action = ai_dir1_pkt_len_right_verify();
    }


    // packet len verify
    Register<bit<16>, bit<16>>(size=MAX_PKT_LEN_INTERVAL, initial_value=0) dir2_left_interval;
    Register<bit<16>, bit<16>>(size=MAX_PKT_LEN_INTERVAL, initial_value=0) dir2_right_interval;

    RegisterAction<bit<16>, _, bit<2>>(dir2_left_interval)
    dir2_left_interval_verify = {
        void apply(inout bit<16> left_side, out bit<2> result) {
            if(metadata.payload_length >= left_side) {
                result = 1;
            } else {
                result = 0;
            }
        }
    };

    RegisterAction<bit<16>, _, bit<2>>(dir2_right_interval)
    dir2_right_interval_verify = {
        void apply(inout bit<16> right_side, out bit<2> result) {
            if(metadata.payload_length <= right_side) {
                result = 1;
            } else {
                result = 0;
            }
        }
    };

    action ai_dir2_pkt_len_left_verify() {
        metadata.dir2_pkt_len_left_verify_res  = dir2_left_interval_verify.execute(metadata.dir2_interval_verify_index);
    }

    // dir2 packet length interval verify 
    @stage(9)
    table ti_dir2_pkt_len_left_verify {
        actions = {ai_dir2_pkt_len_left_verify;}
        size = 1;
        const default_action = ai_dir2_pkt_len_left_verify();
    }

    action ai_dir2_pkt_len_right_verify() {
        metadata.dir2_pkt_len_right_verify_res = dir2_right_interval_verify.execute(metadata.dir2_interval_verify_index);
    }

    @stage(9)
    table ti_dir2_pkt_len_right_verify {
        actions = {ai_dir2_pkt_len_right_verify;}
        size = 1;
        const default_action = ai_dir2_pkt_len_right_verify();
    }





    action ai_final_match() {
        // set the ipv4 header for ident result
        hdr.ipv4.identification = metadata.application_ident_result;
        // digest
        ig_dprsr_md.digest_type = MATCH_SUCCESS;
        // DEBUG
        ig_tm_md.ucast_egress_port = 65;
    }

    @stage(11)
    table ti_final_match {
        key = {
            metadata.matching_state                 :   exact;      
            metadata.flow_direction                 :   exact;      // only hit in direction 2
            metadata.dir1_pkt_len_left_verify_res   :   exact;
            metadata.dir1_pkt_len_right_verify_res  :   exact;
            metadata.dir2_pkt_len_left_verify_res   :   exact;
            metadata.dir2_pkt_len_right_verify_res  :   exact;
        }
        actions = {ai_final_match; ai_nop;}
        size = 1024;
        const default_action = ai_nop();
    }


    // default foward
    action ai_default_forward() {
        ig_tm_md.ucast_egress_port = 64;
    }

    @stage(1)
    table ti_default_forward {
        actions = {ai_default_forward;}
        size = 1;
        const default_action = ai_default_forward();
    }

    


    apply {
        
        ti_default_forward.apply();

        // completion list check
        ti_tcp_completion_list.apply();
        ti_udp_completion_list.apply();

        // pkt gen flow id
        ti_set_pkt_gen_flow_id.apply();

        

        if(hdr.pkt_gen.isValid()) {
            
            ti_expire_completed_list.apply();

            ti_uncompleted_flow_expire.apply();
            ti_clear_flow_flag.apply();
            
            ig_dprsr_md.drop_ctl = 1;

        } 
        else{
            
            // Default forward
            
            ti_init_metadata.apply();
            ti_xor_port.apply();

            ti_get_udp_payload_length.apply();

            ti_get_tcp_hdr_length.apply();
            ti_get_tcp_payload_length.apply();

            
            // get flow_id
            
            ti_get_flow_id.apply();
            // get_flow_direction
            ti_get_direction.apply();

            
            ti_uncompleted_flow_record_time.apply();

            // flow flag
            if(metadata.payload_length != 0) {
                ti_set_flow_flag.apply();
                ti_get_IP_id.apply();
                ti_half_open_connections.apply();
            }
            

            

        
            
            
            if(metadata.half_open_connection_flag == 0 && metadata.payload_length != 0 && metadata.flow_flag != 3) {
                ti_access_server_port.apply();
                ti_access_client_length.apply();

                ti_access_client_payload.apply();
                
                

                if(hdr.tcp.isValid() && hdr.tcp.flags & 0xff != 0x02) {
                    // if(hdr.payload.isValid() && hdr.tcp.flags & 0xff != 0x02) {
                    ti_tcp_flow_matching.apply();
                    // }
                }

                if(hdr.udp.isValid()){
                    ti_udp_flow_matching.apply();
                }

                // pkt_len verify
                ti_dir1_pkt_len_left_verify.apply();
                ti_dir1_pkt_len_right_verify.apply();

                ti_dir2_pkt_len_left_verify.apply();
                ti_dir2_pkt_len_right_verify.apply();
            
                ti_final_match.apply();
            }


            

            // end traffic classification

        }


    }

}
    /*********************  D E P A R S E R  ************************/

control IngressDeparser(packet_out pkt,
    /* User */
    inout my_ingress_headers_t                       hdr,
    in    my_ingress_metadata_t                      metadata,
    /* Intrinsic */
    in    ingress_intrinsic_metadata_for_deparser_t  ig_dprsr_md)
{
    // set digest
    Digest<match_digest_t>() match_digest;
    Digest<expire_digest_t>() expire_digest;
    apply {
        // send digest including: src, dst
        if(ig_dprsr_md.digest_type == MATCH_SUCCESS) {
            match_digest.pack({
                    hdr.ipv4.src_addr,
                    hdr.ipv4.dst_addr,
                    metadata.client_port,
                    metadata.server_port,
                    hdr.ipv4.protocol
            });
        } else if (ig_dprsr_md.digest_type == COMPLETION_EXPIRE) {
            expire_digest.pack({
                    metadata.flow_id
            });
        }
        pkt.emit(hdr);
    }
}


/*************************************************************************
 ****************  E G R E S S   P R O C E S S I N G   *******************
 *************************************************************************/

    /***********************  H E A D E R S  ************************/

struct my_egress_headers_t {
}

    /********  G L O B A L   E G R E S S   M E T A D A T A  *********/

struct my_egress_metadata_t {
}

    /***********************  P A R S E R  **************************/

parser EgressParser(packet_in        pkt,
    /* User */
    out my_egress_headers_t          hdr,
    out my_egress_metadata_t         meta,
    /* Intrinsic */
    out egress_intrinsic_metadata_t  eg_intr_md)
{
    /* This is a mandatory state, required by Tofino Architecture */
    state start {
        pkt.extract(eg_intr_md);
        transition accept;
    }
}

    /***************** M A T C H - A C T I O N  *********************/

control Egress(
    /* User */
    inout my_egress_headers_t                          hdr,
    inout my_egress_metadata_t                         meta,
    /* Intrinsic */    
    in    egress_intrinsic_metadata_t                  eg_intr_md,
    in    egress_intrinsic_metadata_from_parser_t      eg_prsr_md,
    inout egress_intrinsic_metadata_for_deparser_t     eg_dprsr_md,
    inout egress_intrinsic_metadata_for_output_port_t  eg_oport_md)
{
    apply {
    }
}

    /*********************  D E P A R S E R  ************************/

control EgressDeparser(packet_out pkt,
    /* User */
    inout my_egress_headers_t                       hdr,
    in    my_egress_metadata_t                      meta,
    /* Intrinsic */
    in    egress_intrinsic_metadata_for_deparser_t  eg_dprsr_md)
{
    apply {
        pkt.emit(hdr);
    }
}


/************ F I N A L   P A C K A G E ******************************/
Pipeline(
    IngressParser(),
    Ingress(),
    IngressDeparser(),
    EgressParser(),
    Egress(),
    EgressDeparser()
) pipe;

Switch(pipe) main;
