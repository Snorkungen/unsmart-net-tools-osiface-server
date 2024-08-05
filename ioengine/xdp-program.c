//go:build ignore

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* Define needed macros */
#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define ntohs(x) __builtin_bswap16(x)
#define htons(x) __builtin_bswap16(x)
#else
#define ntohs(x) x
#define htons(x) x
#endif

#define ETH_SIZE 1500
#define ETH_P_IP 0x0800
#define ETH_P_IPV6 0x86DD

#define IP_P_TCP 6
#define IP_P_UDP 17
#define IP_P_ICMP 1
#define IP_P_ICMP6 58

#define ICMP_T_ECHO_REPLY 0
#define ICMP_T_ECHO_REQUEST 8
#define ICMP_T_DESTINATION_UNREACH 3
#define ICMP_T_TIME_EXCEEDED 11
#define IMCP_T_BAD_IP 12

#define ICMP6_T_ECHO_REQUEST 128
#define ICMP6_T_ECHO_REPLY 129
#define ICMP6_T_DESTINATION_UNREACH 1
#define ICMP6_T_BAD_PACKET 2
#define ICMP6_T_TIME_EXCEEDED 3
#define ICMP6_T_BAD_IP 4

/* Key that the ebpf program will try to match packets with */
struct packet_key
{
    __u16 ethertype;
    __u16 protocol; // protocol is actually a u8 but for alignment reasons treat as actual u16
    __u16 sport;
    __u16 dport;
    __u8 saddr[16]; // address stored by padding the front i.e. ipv 4 {0, 0, 0, 0 ... 127, 0, 0, 1}
    __u8 daddr[16];
};

/* Define the two maps that will be used */
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, (4096 * 8)); // assume this could hold 16 full ethernet frames
} packet_buffer SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 102); // leave room for x amount of packet transactions
    __type(key, struct packet_key);
    __type(value, __u64); // a number that should probably encode some meaning
} packet_keys SEC(".maps");

/* Define needed headers */
struct eth_hdr
{
    __u8 dmac[6];
    __u8 smac[6];
    __u16 ethertype;
};

struct ip4_hdr
{
    __u8 version_ihl;
    __u8 tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_offset;
    __u8 ttl;
    __u8 protocol;
    __be32 saddr;
    __be32 daddr;
};

struct ip6_hdr
{
    __u8 __ignore[4];
    __be16 payload_length;
    __u8 next_header;
    __u8 hop_limit;

    __be64 saddr[2];
    __be64 daddr[2];
};

struct icmp_hdr
{
    __u8 type;
    __u8 code;
    __u16 csum;
    __u32 roh;
};

// return the amount of bytes that packet moves forward
int read_ip(struct packet_key *pkey, void *data, void *data_end)
{
    if (pkey->ethertype == ETH_P_IP)
    {
        struct ip4_hdr *ip = data;
        if ((void *)(ip + 1) > data_end)
        {
            return -1;
        }

        pkey->protocol = (__u16)ip->protocol;

        // write source and destination addresses into pkey
        *(__be32 *)(pkey->saddr + 12) = ip->saddr;
        *(__be32 *)(pkey->daddr + 12) = ip->daddr;

        // read ihl and move data pointer
        return ((ip->version_ihl & 0xF) << 2);
    }
    else if (pkey->ethertype == ETH_P_IPV6)
    {
        struct ip6_hdr *ip = data;
        if ((void *)(ip + 1) > data_end)
        {
            return -1;
        }

        pkey->protocol = (__u16)ip->next_header; // do not support header options

        // write source and destination addresses into pkey
        // no clue if the following statements work
        *(__be64 *)(pkey->saddr) = ip->saddr[0];
        *(__be64 *)(pkey->saddr + 8) = ip->saddr[1];

        *(__be64 *)(pkey->daddr) = ip->daddr[0];
        *(__be64 *)(pkey->daddr + 8) = ip->daddr[1];

        // move data pointer
        return sizeof(struct ip6_hdr);
    }

    return 0;
}

SEC("xdp")
int match_packets(struct xdp_md *ctx)
{
    int icmp_error = 0;
    struct packet_key pkey = {0};

    void *data_end = (void *)(long)ctx->data_end;
    void *data_start = (void *)(long)ctx->data;
    void *data = data_start;

    // Read ethernet header
    struct eth_hdr *eth = data;
    if ((void *)(eth + 1) > data_end)
    {
        return XDP_ABORTED;
    }

    pkey.ethertype = ntohs(eth->ethertype);

    // move data pointer
    data = (void *)(eth + 1);

    int cnt = read_ip(&pkey, data, data_end);
    if (cnt < 0)
        return XDP_ABORTED;
    else if (cnt == 0)
        return XDP_PASS;

    // move data pointer
    data = data + cnt;

    // Read protocol
    if (pkey.protocol == IP_P_ICMP)
    {
        struct icmp_hdr *icmp = data;
        if ((void *)(icmp + 1) > data_end)
        {
            // I wonder if this would be an off by 1-problem for packets that contain only the header and nothing else
            return XDP_ABORTED;
        }

        switch (icmp->type)
        {
        case ICMP_T_ECHO_REPLY:
        case ICMP_T_ECHO_REQUEST:
            break; // Just forward not reading id or anything
        case ICMP_T_DESTINATION_UNREACH:
        case ICMP_T_TIME_EXCEEDED:
        case IMCP_T_BAD_IP:
            // read the follwing data and stuff
            cnt = read_ip(&pkey, data + sizeof(struct icmp_hdr), data_end);
            if (cnt < 0)
                return XDP_ABORTED;
            if (cnt == 0)
                break;

            icmp_error = 1;
            // move data pointer
            data = data + sizeof(struct icmp_hdr) + cnt;
            break;
        }
    }
    else if (pkey.protocol == IP_P_ICMP6)
    {
        struct icmp_hdr *icmp = data;
        if ((void *)(icmp + 1) > data_end)
        {
            // I wonder if this would be an off by 1-problem for packets that contain only the header and nothing else
            return XDP_ABORTED;
        }

        switch (icmp->type)
        {
        case ICMP6_T_ECHO_REQUEST:
        case ICMP6_T_ECHO_REPLY:
            break; // Just forward not reading id or anything
        case ICMP6_T_DESTINATION_UNREACH:
        case ICMP6_T_TIME_EXCEEDED:
        case ICMP6_T_BAD_IP:
            // case ICMP6_T_BAD_PACKET: // for some reason if this is enabled then the ebpf program won't be loaded
            // read the follwing data and stuff

            cnt = read_ip(&pkey, data + sizeof(struct icmp_hdr), data_end);
            if (cnt < 0)
                return XDP_ABORTED;
            if (cnt == 0)
                break;

            icmp_error = 1;
            // move data pointer
            data = data + sizeof(struct icmp_hdr) + cnt;
            break;
        }
    }

    /* Read TCP or UDP destination and source ports */
    if (pkey.protocol == IP_P_TCP || pkey.protocol == IP_P_UDP)
    {
        // read the sport & dport next 4 bytes
        if ((data + 4) > data_end)
        {
            return -1;
        }

        pkey.sport = ntohs(*(__be16 *)(data));
        pkey.dport = ntohs(*(__be16 *)(data + 2));
    }

    if (icmp_error) // if this is an error swap addresses and ports
    {
        // if this is an error then read swap the ports around
        __u16 tmpp = pkey.sport;
        pkey.sport = pkey.dport;
        pkey.dport = tmpp;

        // swap addresses

        __u64 tmph, tmpl;
        tmph = *(__u64 *)(pkey.saddr);
        tmpl = *(__u64 *)(pkey.saddr + 8);

        *(__u64 *)(pkey.saddr) = *(__u64 *)(pkey.daddr);
        *(__u64 *)(pkey.saddr + 8) = *(__u64 *)(pkey.daddr + 8);

        *(__u64 *)(pkey.daddr) = tmph;
        *(__u64 *)(pkey.daddr + 8) = tmpl;
    }

    __u64 *value = bpf_map_lookup_elem(&packet_keys, &pkey);
    if (value == NULL)
        return XDP_PASS;

    // write packet to packet buffer
    void *rb_data = bpf_ringbuf_reserve(&packet_buffer, ETH_SIZE, 0);
    if (rb_data == NULL)
    {
        return XDP_PASS;
    }

    // Just pass over the entire packet
    data = data_start;

    for (int i = 0; i < ETH_SIZE && data < data_end; i++)
    {
        *(unsigned char *)(rb_data + i) = *(unsigned char *)data++;
    }

    // Write ther data length as into the ethernet header
    *(__u16 *)(rb_data) = htons((unsigned short)(ctx->data_end - ctx->data));

    bpf_ringbuf_submit(rb_data, 0);

    // determine if packet shold be forwarded to operating system
    // TODO: have the value determine if a packet should be dropped
    if (pkey.protocol == IP_P_TCP)
    {
        return XDP_DROP;
    }

    return XDP_PASS;
}

// I do not know what license to use preferably this program would not rely upon licensed code IDK ??
char __license[] SEC("license") = "Dual MIT/GPL";