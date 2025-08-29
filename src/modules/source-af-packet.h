#ifndef NET_THREAT_DETECT_SOURCE_AF_PACKET_H
#define NET_THREAT_DETECT_SOURCE_AF_PACKET_H
#include "utils/queue.h"
#include "utils/threads.h"
#include "utils/util-atomic.h"
#include "modules/tm-threads-common.h"
#include <stdint.h>

#ifndef HAVE_PACKET_FANOUT /* not defined if linux/if_packet.h trying to force */
#define HAVE_PACKET_FANOUT 1
#define PACKET_FANOUT                  18
#endif

/* value for flags */
#define AFP_RING_MODE (1<<0)
#define AFP_ZERO_COPY (1<<1)
#define AFP_SOCK_PROTECT (1<<2)
#define AFP_EMERGENCY_MODE (1<<3)
#define AFP_TPACKET_V3 (1<<4)
#define AFP_VLAN_IN_HEADER (1<<5)
#define AFP_MMAP_LOCKED (1<<6)

#define AFP_COPY_MODE_NONE  0
#define AFP_COPY_MODE_TAP   1

#define AFP_IFACE_NAME_LENGTH 48

/* In kernel the allocated block size is allocated using the formula
 * page_size << order. So default value is using the same formula with
 * an order of 3 which guarantee we have some room in the block compared
 * to standard frame size */
#define AFP_BLOCK_SIZE_DEFAULT_ORDER 3

#define AFPV_CLEANUP(afpv) do {           \
    (afpv)->relptr = NULL;                \
    (afpv)->copy_mode = 0;                \
    (afpv)->peer = NULL;                  \
    (afpv)->mpeer = NULL;                 \
} while(0)

typedef enum {
    CHECKSUM_VALIDATION_DISABLE,
    CHECKSUM_VALIDATION_ENABLE,
    CHECKSUM_VALIDATION_AUTO,
    CHECKSUM_VALIDATION_RXONLY,
    CHECKSUM_VALIDATION_KERNEL,
} ChecksumValidationMode;

typedef struct AFPIfaceConfig_
{
    char iface[AFP_IFACE_NAME_LENGTH];
    /* number of threads */
    int threads;
    /* socket buffer size */
    int buffer_size;
    /* ring size in number of packets */
    int ring_size;
    /* block size for tpacket_v3 in */
    int block_size;
    /* block timeout for tpacket_v3 in milliseconds */
    int block_timeout;
    /* cluster param */
    uint16_t cluster_id;
    int cluster_type;
    /* promisc mode */
    int promisc;
    /* misc use flags including ring mode */
    unsigned int flags;
    int copy_mode;
    ChecksumValidationMode checksum_mode;
    const char *bpf_filter;

    const char *out_iface;
    SC_ATOMIC_DECLARE(unsigned int, ref);
    void (*DerefFunc)(void *);
} AFPIfaceConfig;

typedef struct AFPPeer_ {
  SC_ATOMIC_DECLARE(int, socket);
  SC_ATOMIC_DECLARE(int, sock_usage);
  SC_ATOMIC_DECLARE(int, if_idx);
  int flags;
  SCMutex sock_protect;
  int turn; /**< Field used to store initialisation order. */
  SC_ATOMIC_DECLARE(uint8_t, state);
  struct AFPPeer_ *peer;
  TAILQ_ENTRY(AFPPeer_) next;
  char iface[AFP_IFACE_NAME_LENGTH];
} AFPPeer;

typedef struct AFPPacketVars_
{
  void *relptr;
  AFPPeer *peer; /**< Sending peer for IPS/TAP mode */
  /** Pointer to ::AFPPeer used for capture. Field is used to be able
     * to do reference counting.
   */
  AFPPeer *mpeer;
  uint8_t copy_mode;
} AFPPacketVars;

TmEcode AFPPeersListInit(void);
void TmModuleReceiveAFPRegister (void);
void TmModuleDecodeAFPRegister (void);

int AFPGetLinkType(const char *ifname);

int AFPIsFanoutSupported(uint16_t cluster_id);



#endif //NET_THREAT_DETECT_SOURCE_AF_PACKET_H
