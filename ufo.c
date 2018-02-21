#include <stdio.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/if.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/sockios.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <string.h>
#include <sys/ioctl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <linux/virtio_net.h>
#include <stddef.h>


/* Virtual Machine - may passed through without segmentation by kernel
#define IFACE "virbr0"
// dest MAC 52:54:00:f0:bc:02
// dest  IP 192.168.122.102
#define DEST_MAC0 0x52
#define DEST_MAC1 0x54
#define DEST_MAC2 0x00
#define DEST_MAC3 0xf0
#define DEST_MAC4 0xbc
#define DEST_MAC5 0x02
#define DEST_IP "192.168.122.102"
*/

/* Real HW on the other side of the network - will get segmented before sending */
#define IFACE "enx0050b6655ff2"
// 00:16:cb:b0:d9:85
// 172.16.1.1
#define DEST_MAC0 0x00
#define DEST_MAC1 0x16
#define DEST_MAC2 0xcb
#define DEST_MAC3 0xb0
#define DEST_MAC4 0xd9
#define DEST_MAC5 0x85
#define DEST_IP "172.16.1.1"

// http://www.microhowto.info/howto/calculate_an_internet_protocol_checksum_in_c.html
// "Copying and distribution of this software, with or without
// modification, is permitted in any medium without royalty. This
// software is offered as-is, without any warranty."

uint16_t ip_checksum(void* vdata,size_t length) {
    // Cast the data pointer to one that can be indexed.
    char* data=(char*)vdata;

    // Initialise the accumulator.
    uint32_t acc=0xffff;

    // Handle complete 16-bit blocks.
    for (size_t i=0;i+1<length;i+=2) {
        uint16_t word;
        memcpy(&word,data+i,2);
        acc+=ntohs(word);
        if (acc>0xffff) {
            acc-=0xffff;
        }
    }

    // Handle any partial block at the end of the data.
    if (length&1) {
        uint16_t word=0;
        memcpy(&word,data+length-1,1);
        acc+=ntohs(word);
        if (acc>0xffff) {
            acc-=0xffff;
        }
    }

    // Return the checksum in network byte order.
    return htons(~acc);
}

// Based loosely on:
// http://opensourceforu.com/2015/03/a-guide-to-using-raw-sockets/
// http://www.microhowto.info/howto/send_an_arbitrary_ethernet_frame_using_an_af_packet_socket_in_c.html
int main(int argc, char ** argv) {
	unsigned char * sendbuff = (unsigned char*)malloc(65536);
	struct ifreq ifreq_idx, ifreq_mac, ifreq_ip;
	struct virtio_net_hdr *vnet_hdr;
	struct sockaddr_ll sadr_ll;
	unsigned int total_len = 0;
	unsigned int one = 1;
	struct ethhdr *eth;
	struct iphdr *iph;
	struct udphdr *uh;
	int packet_socket;
	int send_len;

	/* Create raw socket */
	packet_socket = socket(AF_PACKET, SOCK_RAW, IPPROTO_RAW);
	if (packet_socket < 0) {
		printf("socket(): error %d\n", packet_socket);
		return 1;
	}

	/* Get index of sending interface to pass to sendto() */
	memset(&ifreq_idx, 0, sizeof(ifreq_idx));
	strncpy(ifreq_idx.ifr_name, IFACE, IFNAMSIZ-1);
	if (ioctl(packet_socket, SIOCGIFINDEX, &ifreq_idx) < 0) {
		printf("error fetching index of interface '%s'\n", IFACE);
		return 1;
	}

	/* To send a packet, we also need the source MAC... */
	memset(&ifreq_mac, 0, sizeof(ifreq_mac));
	strncpy(ifreq_mac.ifr_name, IFACE, IFNAMSIZ-1);
	if(ioctl(packet_socket, SIOCGIFHWADDR, &ifreq_mac) < 0) {
		printf("error fetching MAC of interface '%s'\n", IFACE);
	}

	/* ... and the source IP */
	memset(&ifreq_ip, 0, sizeof(ifreq_ip));
	strncpy(ifreq_ip.ifr_name, IFACE, IFNAMSIZ-1);
	if(ioctl(packet_socket,SIOCGIFADDR,&ifreq_ip)<0) {
		printf("error in SIOCGIFADDR \n");
	}

	printf("Sending from %s, MAC: %x:%x:%x:%x:%x:%x, IP: %s\n", IFACE,
	       (unsigned char)(ifreq_mac.ifr_hwaddr.sa_data[0]),
	       (unsigned char)(ifreq_mac.ifr_hwaddr.sa_data[1]),
	       (unsigned char)(ifreq_mac.ifr_hwaddr.sa_data[2]),
	       (unsigned char)(ifreq_mac.ifr_hwaddr.sa_data[3]),
	       (unsigned char)(ifreq_mac.ifr_hwaddr.sa_data[4]),
	       (unsigned char)(ifreq_mac.ifr_hwaddr.sa_data[5]),
	       inet_ntoa((((struct sockaddr_in *)&(ifreq_ip.ifr_addr))->sin_addr))
		);


	/* enable the virtio_net header for the socket */
	if (setsockopt(packet_socket, SOL_PACKET, PACKET_VNET_HDR, &one, sizeof(one))) {
		printf("error in setsockopt() enabling PACKET_VNET_HDR\n");
		return 1;
	}

	/* Begin constructing our send buffer by zeroing out */
	memset(sendbuff, 0, 65536);

	/*
	 * Prepare the virtio_net_hdr.
	 * The best reference I can find for this is the header file
	 * linux/virtio_net.h. Good luck.
	 */
	
	vnet_hdr = (struct virtio_net_hdr *)(sendbuff);
	// I'm not sure this is actually considered for UFO as the
	// value doesn't seem to matter.
	vnet_hdr->hdr_len = sizeof(struct ethhdr) + sizeof(struct iphdr);
	// (Ideally you'd do this based on MTU.) UFO doesn't require
	// the udp header to be subtracted as it does IP
	// fragmentation. There's - as far as I can tell - no way to
	// know this without reading the kernel code.
	vnet_hdr->gso_size = 1500 - sizeof(struct iphdr);

	// turn on GSO, in particular UDP (UFO)
	vnet_hdr->gso_type = VIRTIO_NET_HDR_GSO_UDP;

	/*
	 * I cannot find any csum_start value that makes a difference
	 * here, but if the flags are 0, you will get a kernel WARN
	 * from skb_warn_bad_offload.
	 */
	//vnet_hdr->csum_start = sizeof(struct ethhdr)+sizeof(struct iphdr);
	//vnet_hdr->csum_offset = offsetof(struct iphdr, check);
	vnet_hdr->flags = VIRTIO_NET_HDR_F_NEEDS_CSUM;

	total_len += sizeof(struct virtio_net_hdr);

	/* Construct the Ethernet (layer 2) header */
	eth = (struct ethhdr *)(sendbuff + total_len);
	eth->h_source[0] = (unsigned char)(ifreq_mac.ifr_hwaddr.sa_data[0]);
	eth->h_source[1] = (unsigned char)(ifreq_mac.ifr_hwaddr.sa_data[1]);
	eth->h_source[2] = (unsigned char)(ifreq_mac.ifr_hwaddr.sa_data[2]);
	eth->h_source[3] = (unsigned char)(ifreq_mac.ifr_hwaddr.sa_data[3]);
	eth->h_source[4] = (unsigned char)(ifreq_mac.ifr_hwaddr.sa_data[4]);
	eth->h_source[5] = (unsigned char)(ifreq_mac.ifr_hwaddr.sa_data[5]);
	eth->h_dest[0] = DEST_MAC0;
	eth->h_dest[1] = DEST_MAC1;
	eth->h_dest[2] = DEST_MAC2;
	eth->h_dest[3] = DEST_MAC3;
	eth->h_dest[4] = DEST_MAC4;
	eth->h_dest[5] = DEST_MAC5;
	eth->h_proto = htons(ETH_P_IP);
 
	total_len += sizeof(struct ethhdr);

	/* Construct the IP (layer 3) header */
	iph = (struct iphdr*)(sendbuff + total_len);
	iph->ihl = 5;
	iph->version = 4;
	iph->tos = 16;
	iph->id = htons(10201); // we use a fixed IP ID. oh well
	iph->ttl = 64;
	iph->protocol = 17; // UDP
	iph->saddr = inet_addr(inet_ntoa((((struct sockaddr_in *)&(ifreq_ip.ifr_addr))->sin_addr)));
	iph->daddr = inet_addr(DEST_IP); 
 
	total_len += sizeof(struct iphdr);

	/* Construct the UDP (layer 4) header */
	uh = (struct udphdr *)(sendbuff + total_len);
 
	uh->source = htons(23451);
	uh->dest = htons(23452);
	/* We don't set a checksum. This doesn't seem to cause any issues, oddly. */
	uh->check = 0;
 
	total_len += sizeof(struct udphdr);

	/* payload */
	for (unsigned int i=0; i<2000; i++) {
		sendbuff[total_len++] = 'h';
		sendbuff[total_len++] = 'e';
		sendbuff[total_len++] = 'l';
		sendbuff[total_len++] = 'o';
		sendbuff[total_len++] = ' ';
	}
	sendbuff[total_len++] = '\n';
	sendbuff[total_len++] = '\n';


	/* Set the lengths */
	// At least for UDP, we set the size of the whole packet before segmenting.
	// This is because UFO just does IP fragmentation of the datagram.
	uh->len = htons(total_len - sizeof(struct iphdr) - sizeof(struct ethhdr) - sizeof(struct virtio_net_hdr));
	iph->tot_len = htons(total_len - sizeof(struct ethhdr) - sizeof(struct virtio_net_hdr));

	// We do need an IP checksum, and I cannot figure out how to get the kernel to do it for me.
	iph->check = ip_checksum((sendbuff + sizeof(struct virtio_net_hdr) + sizeof(struct ethhdr)), (sizeof(struct iphdr)));

	/*
	 * prepare to send: tell the kernel where to send the packet
	 * and through what interface
	 */
	sadr_ll.sll_ifindex = ifreq_idx.ifr_ifindex; // index of interface
	sadr_ll.sll_halen = ETH_ALEN; // length of destination mac address
	sadr_ll.sll_addr[0] = DEST_MAC0;
	sadr_ll.sll_addr[1] = DEST_MAC1;
	sadr_ll.sll_addr[2] = DEST_MAC2;
	sadr_ll.sll_addr[3] = DEST_MAC3;
	sadr_ll.sll_addr[4] = DEST_MAC4;
	sadr_ll.sll_addr[5] = DEST_MAC5;
	// if GSO is off, the packet will be sent even if this is not set.
	// but if GSO is on, this seems to be absolutely required.
	sadr_ll.sll_protocol = htons(ETH_P_IP);

	/* actually send the packet */
	send_len = sendto(packet_socket, sendbuff,
			  total_len, 0,
			  (const struct sockaddr*)&sadr_ll,
			  sizeof(struct sockaddr_ll));
	if (send_len < 0) {
		printf("error in sending....send_len=%d\n", send_len);
		perror("sendto");
		return -1;
	}
	
	printf("sent %d bytes (total_len = %u)\n", send_len, total_len);

	return 0;      
}
