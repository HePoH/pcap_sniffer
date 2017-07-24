#include "../include/core.h"

void list_net_devs() {
	int rtn = 0;
	pcap_if_t *net_devs_list = NULL, *cur_dev = NULL;
	char err_buf[PCAP_ERRBUF_SIZE];

	rtn = pcap_findalldevs(&net_devs_list, err_buf);
	if (rtn == -1) {
		fprintf(stderr, "pcap_findalldevs failed: couldn't get all network devices: %s\n", err_buf);
		exit(EXIT_FAILURE);
	}

	printf("\nAvailable network devices list:\n");

	cur_dev = net_devs_list;
	while(cur_dev) {
		printf("%s\t%s\t%s\t\n", cur_dev->name, cur_dev->description ? cur_dev->description : "(no description)"/*, inet_ntoa((struct in_addr) *(cur_dev->addresses)->addr)*/);

		cur_dev = cur_dev->next;
	}

	if (net_devs_list)
		pcap_freealldevs(net_devs_list);
}

void pckt_hndl(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
	/* code */
}
