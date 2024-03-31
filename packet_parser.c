/* This file parses ICMP packets only, by checking
 * the destination IP and if the packet is an ICMP 
 * packet or not. 
 */

/* All the parse functions are defined in parser.h
 * The parse functions return the value -1 if either
 * the header doesn't match or if there is an out of
 * bounds memory access.
 */

#include "./parser.h"
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

/* Set the source ip of packet you want to drop here
 * Convert this using inet_pton, cannot be done here 
 * as external functions cannot be combiled with BPF code.
 * Other option is to implement it using bpf maps.
 */

//long int src_ip4 = 175810752; // IP 192.168.122.10
long int src_ip4 = 16777343; // IP 192.168.122.10
long int src_ip6[4] = {215693203,8003952745,1801513092,9030242305}; //IP 2001:1890:110c:1111::a246
int port_tcp = 8080;
int port_udp = 9000;


/* This IPV6 value is wrong, and I couldn't find a 
 * proper way to convert IPV6 addresses to decimal,
 * inet_ptons wasn't giving proper output.
 * This code should work if the IPV6 address matches
 * as the same logic is applied for IPV4 and it works 
 * for IPV4. I confirmed this by testing without the
 * IP address check.
 * */


SEC("xdp")
int icmp_parser(struct xdp_md *ctx) {

	void *data_end = (void*)(long)ctx->data_end;
	void *data = (void*)(long)ctx->data;

	struct ethhdr *eth;
	struct iphdr  *ip;
	struct ipv6hdr *ipv6;
	struct icmphdr *icmp;
	struct icmp6hdr *icmp6;
	struct tcphdr *tcp;
	struct udphdr *udp;
	struct hdr_cursor nh;
	int nh_type;

	nh.pos = data;
	nh_type = parse_ethhdr(&nh,data_end,&eth); //Parsing the ethernet header
	if(nh_type == -1)
		goto out;
	if(nh_type == htons(ETH_P_IPV6)){//Checking IP version 
		nh_type = parse_ip6hdr(&nh,data_end,&ipv6);
		if(nh_type == -1)
			goto out;
		if(ipv6->saddr.in6_u.u6_addr32 == src_ip6){
			if(ipv6->nexthdr == IPPROTO_ICMPV6){
				nh_type = parse_icmp6hdr(&nh,data_end,&icmp6);
				if(nh_type != -1)
					return XDP_DROP;
				else
					goto out;
			}
			if(ipv6->nexthdr == IPPROTO_TCP){
				nh_type = parse_tcphdr(&nh,data_end,&tcp);
				if(nh_type != -1){
					if(tcp->dest == htons(port_tcp)){
						return XDP_DROP;
					}
				}
				else
					goto out;
				
			}
			if(ipv6->nexthdr == IPPROTO_UDP){
				nh_type = parse_udphdr(&nh,data_end,&udp);
				if(nh_type != -1){
					if(udp->dest == htons(port_udp)){
						return XDP_DROP;
					}
				}
				else
					goto out;
			}
		}
	}
	if(nh_type == htons(ETH_P_IP)){
		nh_type = parse_iphdr(&nh,data_end,&ip);
		if(nh_type == -1)
			goto out;
		if(ip->saddr == src_ip4){
			if(ip->protocol == IPPROTO_ICMP){
				nh_type = parse_icmphdr(&nh,data_end,&icmp);
				if(nh_type != -1)
					return XDP_DROP;
				else
					goto out;
			}
			if(ip->protocol == IPPROTO_TCP){
				nh_type = parse_tcphdr(&nh,data_end,&tcp);
				if(nh_type != -1){
					if(tcp->dest == htons(port_tcp)){
						return XDP_DROP;
					}
				}
				else
					goto out;
			}
			if(ip->protocol == IPPROTO_UDP){
				nh_type = parse_udphdr(&nh,data_end,&udp);
				if(nh_type != -1){
					if(udp->dest == htons(port_udp)){
						return XDP_DROP;
					}
				}
				else
					goto out;
			}
		}
	}

out:
	return XDP_PASS;

}

char _license[] SEC("license") = "GPL";
