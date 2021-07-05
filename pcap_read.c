#include <pcap/pcap.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <string.h>

#define usage printf("usage: xx -f pcap_file\n");

static int
dump_pcap(const char* pcap_file);
static void
dump_packet(const struct pcap_pkthdr* header, const uint8_t* packet);
static const uint8_t*
dump_ether_header(const uint8_t* packet);
static void
dump_ip(const uint8_t* packet);
static void
dump_tcp(const uint8_t* packet);

int
main(int argc, char* argv[])
{
  char ch;
  const char* pcap_file = NULL;

  while ((ch = getopt(argc, argv, "f:")) != -1) {
    switch (ch) {
      case 'f':
        pcap_file = optarg;
        break;
      default:
        usage;
        return -1;
    }
  }

  if (!pcap_file) {
    usage;
    return -1;
  }

  return dump_pcap(pcap_file);
}

static int
dump_pcap(const char* pcap_file)
{
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_offline(pcap_file, errbuf);
  if (handle == NULL) {
    printf("Could not open file %s: %s\n", pcap_file, errbuf);
    return -1;
  }

  struct pcap_pkthdr header;
  const uint8_t *packet;
  while (packet = pcap_next(handle, &header)) {
    dump_packet(&header, packet);
  }

  pcap_close(handle);
  return 0;
}

static void
dump_packet(const struct pcap_pkthdr* header, const uint8_t* packet)
{
  printf("================================\n");
  const uint8_t* data = dump_ether_header(packet);
}

static const uint8_t*
dump_ether_header(const uint8_t* packet)
{
  printf("source mac address\n");
  int i = 0;
  for (int j = i; j < i + 6; j++) {
    printf("%x:", packet[j]);
  }
  i += 6;
  printf("\n");
  printf("dest mac address\n");
  for (int j = i; j < i + 6; j++) {
    printf("%x:", packet[j]);
  }
  i += 6;
  printf("\n");
  uint16_t ether_type;
  memcpy(&ether_type, &packet[i], 2);
  i += 2;
  switch (ntohs(ether_type)) {
    case 0x0800:
      printf("ether type %x ip\n", ntohs(ether_type));
      dump_ip(&packet[i]);
      break;
    default:
      printf("unknown ether type %x\n", ntohs(ether_type));
      break;
  }
  
  return &packet[i];
}

static void
dump_ip(const uint8_t* packet)
{
  printf("version %d\n", packet[0] >> 4);
  printf("length %d\n", packet[0] & 0x0f);
  printf("tos %x\n", packet[1]);
  uint16_t total_length;
  memcpy(&total_length, &packet[2], 2);
  printf("total length %d\n", ntohs(total_length));
  uint16_t identification;
  memcpy(&identification, &packet[4], 2);
  printf("identification %x\n", ntohs(identification));
  printf("flags %x\n", packet[6] >> 5);
  uint16_t fragment_offset;
  memcpy(&fragment_offset, &packet[6], 2);
  ((uint8_t*)&fragment_offset)[0] &= 0x1f; 
  printf("fragment offset %x\n", ntohs(fragment_offset));
  printf("time to live %x\n", packet[8]);
  
  uint16_t header_checksum;
  memcpy(&header_checksum, &packet[10], 2);
  printf("header checksum %x\n", header_checksum);
  uint16_t cal_checksum = 0;
  for (int i = 0; i < 10; i++) {
    if (i != 5) {
      uint16_t val;
      memcpy(&val, &packet[2 * i], 2);
      cal_checksum += val;
    }
  }
  uint8_t carry = ((uint8_t*)&cal_checksum)[0] >> 4;
  ((uint8_t*)&cal_checksum)[0] &= 0x0f;
  cal_checksum += carry;
  printf("cal checksum %x\n", cal_checksum);
  printf("source address %d.%d.%d.%d\n", packet[12], packet[13], packet[14], packet[15]);
  printf("dest address %d.%d.%d.%d\n", packet[16], packet[17], packet[18], packet[19]);
  switch (packet[9]) {
    case 0x06:
      printf("protocol tcp 0x06\n");
      dump_tcp(&packet[20]);
      break;
    case 0x11:
      printf("protocol udp 0x11\n");
      break;
    default:
      printf("unknown protocol %x\n", packet[9]);
      break;
  }
}

static void
dump_tcp(const uint8_t* packet)
{
  uint16_t port;
  memcpy(&port, &packet[0], 2);
  printf("src port %d\n", ntohs(port));

  memcpy(&port, &packet[2], 2);
  printf("dst port %d\n", ntohs(port));

  uint32_t seq;
  memcpy(&seq, &packet[4], 4);
  printf("seq %u\n", ntohl(seq));

  uint32_t ack;
  memcpy(&ack, &packet[8], 4);
  printf("ack %u\n", ntohl(ack));

  uint8_t data_offset = packet[12] >> 4;
  printf("data offset %d\n", data_offset);
  if (packet[12] & 0x1)
    printf("ns is set\n");
  if (packet[13] & 0x80)
    printf("cwr is set\n");
  if (packet[13] & 0x40)
    printf("ece is set\n");
  if (packet[13] & 0x20)
    printf("urg is set\n");
  if (packet[13] & 0x10)
    printf("ack is set\n");
  if (packet[13] & 0x8)
    printf("psh is set\n");
  if (packet[13] & 0x4)
    printf("rst is set\n");
  if (packet[13] & 0x2)
    printf("syn is set\n");
  if (packet[13] & 0x1)
    printf("fin is set\n");
  uint16_t wsize;
  memcpy(&wsize, &packet[14], 2);
  printf("windows size %d\n", ntohs(wsize));
  uint16_t checksum;
  memcpy(&checksum, &packet[16], 2);
  printf("checksum %x\n", checksum);
  uint16_t urg_pointer;
  memcpy(&urg_pointer, &packet[18], 2);
  printf("urg pointer %d\n", ntohs(urg_pointer));

  const uint8_t* options = &packet[20];
  int16_t options_length = data_offset * 4 - 20;
  uint8_t option_length;
  uint16_t p = 0;
  while (p < options_length) {
    uint8_t option_kind = options[p];
    p++;
    switch (option_kind) {
      case 5:
        option_length = options[p];
        p++;
        printf("option sack\n");
        uint16_t q = 0;
        while (q < option_length - 2) {
          uint32_t edge;
          memcpy(&edge, &options[p + q], 4);
          printf("left edge %u\n", ntohl(edge));
          q += 4;
          memcpy(&edge, &options[p + q], 4);
          printf("right edge %u\n", ntohl(edge));
          q += 4;
        }
        p += (option_length - 2);
        break;
      case 0:
      case 1:
        printf("reserved option %d\n", option_kind);
        break;
      case 8:
        option_length = options[p];
        p++;
        if (option_length != 10) {
          printf("timestamp option invalid\n");
        } else {
          printf("option timestamp\n");
          uint32_t tm;
          memcpy(&tm, &options[p], 4);
          printf("timestamp %u\n", ntohl(tm));
          p += 4;
          memcpy(&tm, &options[p], 4);
          printf("timestamp echo reply %u\n", ntohl(tm));
          p += 4;
        }
        break;
      default:
        printf("unknown option kind %d\n", option_kind);
        break;
    }
  }
}
