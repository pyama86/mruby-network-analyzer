// base: https://github.com/lsanotes/iftop
/*
** mrb_networkanalyzer.c - NetworkAnalyzer class
**
** Copyright (c) pyama86 2017
**
** See Copyright Notice in LICENSE
*/
#include "mruby.h"
#include "mruby/array.h"
#include "mruby/class.h"
#include "mruby/data.h"
#include "mruby/hash.h"
#include <signal.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip6.h>
#include <pcap.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>

#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "addr_hash.h"
#include "ether.h"
#include "ethertype.h"
#include "hash.h"
#include "iftop.h"
#include "ip.h"
#include "tcp.h"
#define DONE mrb_gc_arena_restore(mrb, 0);
#define CAPTURE_LENGTH 256
#define HISTORY_LENGTH 20
#define HOSTNAME_LENGTH 256
#define WAIT_TIME 10
#define PushHistory(type)                                                                          \
  do {                                                                                             \
    if (d->type[i] != 0) {                                                                     \
      mrb_ary_push(mrb, ary_##type##_history, mrb_fixnum_value(d->type[i]));                       \
    }                                                                                              \
  } while (0)

typedef struct {
  unsigned char if_hw_addr[6];
  struct in_addr if_ip_addr;
  struct in6_addr if_ip6_addr;
  int have_hw_addr;
  int have_ip_addr;
  int have_ip6_addr;
  hash_type *history;
  history_type history_totals;
  int history_pos;
  int history_len;
  time_t last_timestamp;
  pcap_t *pd;
} mrb_networkanalyzer_data;

typedef struct {
  mrb_state *mrb;
  mrb_networkanalyzer_data *data;
} packet_loop_conf;

static void mrb_mruby_network_analyzer_data_free(mrb_state *mrb, void *p)
{
  mrb_networkanalyzer_data *data = p;
  mrb_free(mrb, data->history);
  mrb_free(mrb, data);
}

static const struct mrb_data_type mrb_networkanalyzer_data_type = {
    "mrb_networkanalyzer_data", mrb_mruby_network_analyzer_data_free,
};

int get_addrs_ioctl(mrb_state *mrb, mrb_networkanalyzer_data *data, char *interface)
{
  int s;
  struct ifreq ifr = {};
  int got_hw_addr = 0;
  int got_ip_addr = 0;
  int got_ip6_addr = 0;

  s = socket(AF_INET, SOCK_DGRAM, 0);
  if (s == -1) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "socket error");
  }

  memset(&data->if_hw_addr, 0, 6);
  strncpy(ifr.ifr_name, interface, IFNAMSIZ);

  if (ioctl(s, SIOCGIFHWADDR, &ifr) < 0) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "Error getting hardware address for interface: %S\n",
               mrb_str_new_cstr(mrb, interface));
  } else {
    memcpy(&data->if_hw_addr, ifr.ifr_hwaddr.sa_data, 6);
    got_hw_addr = 1;
  }

  (*(struct sockaddr_in *)&ifr.ifr_addr).sin_family = AF_INET;
  if (ioctl(s, SIOCGIFADDR, &ifr) >= 0) {
    memcpy(&data->if_ip_addr, &((*(struct sockaddr_in *)&ifr.ifr_addr).sin_addr),
           sizeof(struct in_addr));
    got_ip_addr = 2;
  }

  close(s);

  return got_hw_addr + got_ip_addr + got_ip6_addr;
}

int ip_addr_match(struct in_addr if_ip_addr, struct in_addr addr)
{
  return addr.s_addr == if_ip_addr.s_addr;
}

int ip6_addr_match(struct in6_addr *if_ip6_addr, struct in6_addr *addr)
{
  return IN6_ARE_ADDR_EQUAL(addr, &if_ip6_addr);
}

void init_history(mrb_state *mrb, mrb_networkanalyzer_data *data)
{
  data->history = addr_hash_create(mrb);
  data->history_pos = 0;
  data->history_len = 1;
  data->last_timestamp = time(NULL);
  memset(&data->history_totals, 0, sizeof data->history_totals);
}

void assign_addr_pair(addr_pair *ap, struct ip *iptr, int flip)
{
  unsigned short int src_port = 0;
  unsigned short int dst_port = 0;

  /* Arrange for predictable values. */
  memset(ap, '\0', sizeof(*ap));

  if (IP_V(iptr) == 4) {
    ap->af = AF_INET;
    if (iptr->ip_p == IPPROTO_TCP || iptr->ip_p == IPPROTO_UDP) {
      struct tcphdr *thdr = ((void *)iptr) + IP_HL(iptr) * 4;
      src_port = ntohs(thdr->th_sport);
      dst_port = ntohs(thdr->th_dport);
    }

    if (flip == 0) {
      ap->src = iptr->ip_src;
      ap->src_port = src_port;
      ap->dst = iptr->ip_dst;
      ap->dst_port = dst_port;
    } else {
      ap->src = iptr->ip_dst;
      ap->src_port = dst_port;
      ap->dst = iptr->ip_src;
      ap->dst_port = src_port;
    }
  } /* IPv4 */
  else if (IP_V(iptr) == 6) {
    /* IPv6 packet seen. */
    struct ip6_hdr *ip6tr = (struct ip6_hdr *)iptr;

    ap->af = AF_INET6;

    if ((ip6tr->ip6_nxt == IPPROTO_TCP) || (ip6tr->ip6_nxt == IPPROTO_UDP)) {
      struct tcphdr *thdr = ((void *)ip6tr) + 40;

      src_port = ntohs(thdr->th_sport);
      dst_port = ntohs(thdr->th_dport);
    }

    if (flip == 0) {
      memcpy(&ap->src6, &ip6tr->ip6_src, sizeof(ap->src6));
      ap->src_port = src_port;
      memcpy(&ap->dst6, &ip6tr->ip6_dst, sizeof(ap->dst6));
      ap->dst_port = dst_port;
    } else {
      memcpy(&ap->src6, &ip6tr->ip6_dst, sizeof(ap->src6));
      ap->src_port = dst_port;
      memcpy(&ap->dst6, &ip6tr->ip6_src, sizeof(ap->dst6));
      ap->dst_port = src_port;
    }
  }
}
history_type *history_create(mrb_state *mrb)
{
  history_type *h;
  h = xcalloc(mrb, 1, sizeof *h);
  return h;
}

static void handle_ip_packet(mrb_state *mrb, mrb_networkanalyzer_data *data, struct ip *iptr, int hw_dir)
{
  int direction = 0;
  addr_pair ap;
  history_type *ht;
  unsigned int len = 0;
  struct in6_addr scribdst;
  struct in6_addr scribsrc;
  union {
    history_type **ht_pp;
    void **void_pp;
  } u_ht = {&ht};
  struct ip6_hdr *ip6tr = (struct ip6_hdr *)iptr;

  memset(&ap, '\0', sizeof(ap));

  if (IP_V(iptr) == 4 || IP_V(iptr) == 6) {
    if (hw_dir == 1) {
      assign_addr_pair(&ap, iptr, 0);
      direction = 1;
    } else if (hw_dir == 0) {
      // Packet incoming
      assign_addr_pair(&ap, iptr, 1);
      direction = 0;
    } else if ((IP_V(iptr) == 4) && data->have_ip_addr &&
               ip_addr_match(data->if_ip_addr, iptr->ip_src)) {
      // outgoing
      assign_addr_pair(&ap, iptr, 0);
      direction = 1;
    } else if ((IP_V(iptr) == 4) && data->have_ip_addr &&
               ip_addr_match(data->if_ip_addr, iptr->ip_dst)) {
      // incoming
      assign_addr_pair(&ap, iptr, 1);
      direction = 0;
    } else if ((IP_V(iptr) == 6) && data->have_ip6_addr &&
               ip6_addr_match(&data->if_ip6_addr, &ip6tr->ip6_src)) {
      // outgoing
      assign_addr_pair(&ap, iptr, 0);
      direction = 1;
    } else if ((IP_V(iptr) == 6) && data->have_ip6_addr &&
               ip6_addr_match(&data->if_ip6_addr, &ip6tr->ip6_dst)) {
      // incoming
      assign_addr_pair(&ap, iptr, 1);
      direction = 0;
    } else if ((IP_V(iptr) == 4) && (iptr->ip_src.s_addr < iptr->ip_dst.s_addr)) {
      assign_addr_pair(&ap, iptr, 1);
      direction = 0;
    } else if (IP_V(iptr) == 4) {
      assign_addr_pair(&ap, iptr, 0);
      direction = 0;
    }
  }

  if (hash_find(data->history, &ap, u_ht.void_pp) == HASH_STATUS_KEY_NOT_FOUND) {
    ht = history_create(mrb);
    hash_insert(mrb, data->history, &ap, ht);
  }

  switch (IP_V(iptr)) {
  case 4:
    len = ntohs(iptr->ip_len);
    break;
  case 6:
    len = ntohs(ip6tr->ip6_plen) + 40;
  default:
    break;
  }

  ht->last_write = data->history_pos;
  if (((IP_V(iptr) == 4) && (iptr->ip_src.s_addr == ap.src.s_addr)) ||
      ((IP_V(iptr) == 6) && !memcmp(&ip6tr->ip6_src, &ap.src6, sizeof(ap.src6)))) {
    ht->sent[data->history_pos] += len;
    ht->total_sent += len;
  } else {
    ht->recv[data->history_pos] += len;
    ht->total_recv += len;
  }

  if (direction == 0) {
    data->history_totals.recv[data->history_pos] += len;
    data->history_totals.total_recv += len;
  } else {
    data->history_totals.sent[data->history_pos] += len;
    data->history_totals.total_sent += len;
  }

}

static void handle_eth_packet(unsigned char *args, const struct pcap_pkthdr *pkthdr,
                              const unsigned char *packet)
{
  struct ether_header *eptr;
  int ether_type;
  const unsigned char *payload;
  mrb_networkanalyzer_data *data;
  packet_loop_conf *c;
  c = (packet_loop_conf *)args;

  data = c->data;
  eptr = (struct ether_header *)packet;
  ether_type = ntohs(eptr->ether_type);
  payload = packet + sizeof(struct ether_header);

  if (ether_type == ETHERTYPE_8021Q) {
    struct vlan_8021q_header *vptr;
    vptr = (struct vlan_8021q_header *)payload;
    ether_type = ntohs(vptr->ether_type);
    payload += sizeof(struct vlan_8021q_header);
  }

  if (ether_type == ETHERTYPE_IP || ether_type == ETHERTYPE_IPV6) {
    struct ip *iptr;
    int dir = -1;
    if (data->have_hw_addr && memcmp(eptr->ether_shost, data->if_hw_addr, 6) == 0) {
      dir = 1;
    } else if (data->have_hw_addr && memcmp(eptr->ether_dhost, data->if_hw_addr, 6) == 0) {
      dir = 0;
    } else if (memcmp("\xFF\xFF\xFF\xFF\xFF\xFF", eptr->ether_dhost, 6) == 0) {
      dir = 0;
    }

    iptr = (struct ip *)(payload);
    handle_ip_packet(c->mrb, c->data, iptr, dir);
  }
}

void packet_init(mrb_state *mrb, mrb_networkanalyzer_data *data, char *if_name)
{
  char errbuf[PCAP_ERRBUF_SIZE];
  int result;
  result = get_addrs_ioctl(mrb, data, if_name);
  if (result < 0) {
    mrb_raise(mrb, E_RUNTIME_ERROR, "get_addrs_ioctl error");
  }

  data->have_hw_addr = result & 0x01;
  data->have_ip_addr = result & 0x02;
  data->have_ip6_addr = result & 0x04;
}

static mrb_value fetch_packet_history(mrb_state *mrb,mrb_networkanalyzer_data *data)
{
  char src_host[HOSTNAME_LENGTH];
  char dst_host[HOSTNAME_LENGTH];
  char src_port[HOSTNAME_LENGTH];
  char dst_port[HOSTNAME_LENGTH];
  mrb_value current, ary_recv_history, ary_sent_history;
  mrb_value h;
  hash_node_type *n = NULL;

  current = mrb_ary_new(mrb);
  while (hash_next_item(data->history, &n) == HASH_STATUS_OK) {
    addr_pair ap = *(addr_pair *)n->key;
    history_type *d = (history_type *)n->rec;

    h = mrb_hash_new(mrb);
    inet_ntop(ap.af, &ap.src6, src_host, sizeof(src_host));
    inet_ntop(ap.af, &ap.dst6, dst_host, sizeof(dst_host));
    snprintf(src_port, HOSTNAME_LENGTH, ":%d", ap.src_port);
    snprintf(dst_port, HOSTNAME_LENGTH, ":%d", ap.dst_port);

    mrb_hash_set(mrb, h, mrb_str_new_cstr(mrb, "src_host"), mrb_str_new_cstr(mrb, src_host));
    mrb_hash_set(mrb, h, mrb_str_new_cstr(mrb, "dst_host"), mrb_str_new_cstr(mrb, dst_host));
    mrb_hash_set(mrb, h, mrb_str_new_cstr(mrb, "src_port"), mrb_str_new_cstr(mrb, src_port));
    mrb_hash_set(mrb, h, mrb_str_new_cstr(mrb, "dst_port"), mrb_str_new_cstr(mrb, dst_port));
    mrb_hash_set(mrb, h, mrb_str_new_cstr(mrb, "total_sent"), mrb_fixnum_value(d->total_sent));
    mrb_hash_set(mrb, h, mrb_str_new_cstr(mrb, "total_recv"), mrb_fixnum_value(d->total_recv));

    ary_recv_history = mrb_ary_new(mrb);
    ary_sent_history = mrb_ary_new(mrb);
    for (int i = 0; i < HISTORY_LENGTH; i++) {
      PushHistory(sent);
      PushHistory(recv);
    }
    mrb_hash_set(mrb, h, mrb_str_new_cstr(mrb, "sent_history"), ary_sent_history);
    mrb_hash_set(mrb, h, mrb_str_new_cstr(mrb, "recv_history"), ary_recv_history);
    mrb_ary_push(mrb, current, h);
  }
  return current;
}

static mrb_value mrb_networkanalyzer_collect(mrb_state *mrb, mrb_value self)
{
  mrb_networkanalyzer_data *data;
  int dlt;
  int retry=0;
  char *if_name;
  int if_name_len;
  char ebuf[PCAP_ERRBUF_SIZE];
  mrb_int sec, max;
  max = -1;

  mrb_get_args(mrb, "zi|i", &if_name, &sec, &max);

  data = (mrb_networkanalyzer_data *)mrb_malloc(mrb, sizeof(mrb_networkanalyzer_data));
  init_history(mrb, data);
  packet_init(mrb, data, if_name);

  if ((data->pd = pcap_open_live(if_name, CAPTURE_LENGTH, 1, 1000, ebuf)) == NULL) {
    mrb_raisef(mrb, E_RUNTIME_ERROR, "pcap open error %S", mrb_str_new_cstr(mrb, ebuf));
  }

  dlt = pcap_datalink(data->pd);
  if (dlt == DLT_EN10MB) {
    sleep(sec);
    packet_loop_conf c = {mrb, data};
    pcap_dispatch(data->pd, max, handle_eth_packet, &c);
    pcap_close(data->pd);
  } else {
    mrb_raise(mrb, E_RUNTIME_ERROR, "unsupported datalink type");
  }

  return fetch_packet_history(mrb, data);
}

void mrb_mruby_network_analyzer_gem_init(mrb_state *mrb)
{
  struct RClass *networkanalyzer;
  networkanalyzer = mrb_define_class(mrb, "NetworkAnalyzer", mrb->object_class);
  mrb_define_class_method(mrb, networkanalyzer, "collect", mrb_networkanalyzer_collect, MRB_ARGS_ARG(2, 1));
  MRB_SET_INSTANCE_TT(networkanalyzer, MRB_TT_DATA);
  DONE;
}

void mrb_mruby_network_analyzer_gem_final(mrb_state *mrb)
{
}
