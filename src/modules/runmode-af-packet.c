#include <stdio.h>
#include <linux/if_packet.h>
#include <unistd.h>

#include "runmode-af-packet.h"
#include "modules/tm-threads.h"
#include "modules/tm-modules.h"
#include "runmodes.h"
#include "utils/conf.h"
#include "utils/util-mem.h"
#include "utils/util-conf.h"
#include "utils/util-byte.h"
#include "utils/util-time.h"

/* if cluster id is not set, assign it automagically, uniq value per
 * interface. */
static int cluster_id_auto = 1;
extern int max_pending_packets;

const char *RunModeAFPGetDefaultMode(void)
{
    return "workers";
}

static int RunModeSetLiveCaptureWorkersForDevice(const char *recv_mod_name,
                                                 const char *decode_mod_name, const char *thread_name,
                                                 const char *live_dev,void *aconf,
                                                 unsigned char single_mode)
{
    int threads_count;

    if (single_mode) {
        threads_count = 1;
    } else{
        threads_count = 1;
    }
    /* create the threads */
    for (int thread = 0; thread < threads_count; thread++) {
        char tname[TM_THREAD_NAME_MAX];
        TmModule *tm_module = NULL;
        const char *visual_devname = live_dev;
        if (single_mode) {
            snprintf(tname, sizeof(tname), "%s#01-%s", thread_name, visual_devname);
        } else {
            snprintf(tname, sizeof(tname), "%s#%02d-%s", thread_name,
                     thread+1, visual_devname);
        }
        ThreadVars *tv = TmThreadCreatePacketHandler(tname,
                                                     "packetpool", "packetpool",
                                                     "packetpool", "packetpool",
                                                     "pktacqloop");
        if (tv == NULL) {
            FatalError(SC_ERR_THREAD_CREATE, "TmThreadsCreate failed");
        }

        tm_module = TmModuleGetByName(recv_mod_name);
        if (tm_module == NULL) {
            FatalError(SC_ERR_INVALID_VALUE, "TmModuleGetByName failed for %s", recv_mod_name);
        }
        TmSlotSetFuncAppend(tv, tm_module, aconf);

        tm_module = TmModuleGetByName(decode_mod_name);
        if (tm_module == NULL) {
            FatalError(SC_ERR_INVALID_VALUE, "TmModuleGetByName %s failed", decode_mod_name);
        }
        TmSlotSetFuncAppend(tv, tm_module, NULL);

        tm_module = TmModuleGetByName("FlowWorker");
        if (tm_module == NULL) {
            FatalError(SC_ERR_RUNMODE, "TmModuleGetByName for FlowWorker failed");
        }
        TmSlotSetFuncAppend(tv, tm_module, NULL);

        if (TmThreadSpawn(tv) != TM_ECODE_OK) {
            FatalError(SC_ERR_THREAD_SPAWN, "TmThreadSpawn failed");
        }
    }

    return 0;
}

static void AFPDerefConfig(void *conf)
{
    AFPIfaceConfig *pfp = (AFPIfaceConfig *)conf;
    /* Pcap config is used only once but cost of this low. */
    if (SC_ATOMIC_SUB(pfp->ref, 1) == 1) {
        SCFree(pfp);
    }
}

static void *ParseAFPConfig(const char *iface)
{
    const char *threadsstr = NULL;
    ConfNode *if_root;
    ConfNode *if_default = NULL;
    ConfNode *af_packet_node;
    //const char *tmpclusterid;
    const char *tmpctype;
    const char *copymodestr;
    intmax_t value;
    int boolval;
    const char *bpf_filter = NULL;
    const char *out_iface = NULL;
    int cluster_type = PACKET_FANOUT_HASH;
    const char *active_runmode = RunmodeGetActive();

    if (iface == NULL) {
        return NULL;
    }

    AFPIfaceConfig *aconf = SCCalloc(1, sizeof(*aconf));
    if (unlikely(aconf == NULL)) {
        return NULL;
    }

    strlcpy(aconf->iface, iface, sizeof(aconf->iface));
    aconf->threads = 0;
    SC_ATOMIC_INIT(aconf->ref);
    (void) SC_ATOMIC_ADD(aconf->ref, 1);
    aconf->buffer_size = 0;
    aconf->cluster_id = 1;
    aconf->cluster_type = cluster_type | PACKET_FANOUT_FLAG_DEFRAG;
    aconf->promisc = 1;
    aconf->checksum_mode = CHECKSUM_VALIDATION_KERNEL;
    aconf->DerefFunc = AFPDerefConfig;
    aconf->flags = AFP_RING_MODE;
    aconf->bpf_filter = NULL;
    aconf->out_iface = NULL;
    aconf->copy_mode = AFP_COPY_MODE_NONE;
    aconf->block_timeout = 10;
    aconf->block_size = getpagesize() << AFP_BLOCK_SIZE_DEFAULT_ORDER;

    if (ConfGet("bpf-filter", &bpf_filter) == 1) {
        if (strlen(bpf_filter) > 0) {
            aconf->bpf_filter = bpf_filter;
            SCLogConfig("Going to use command-line provided bpf filter '%s'",
                        aconf->bpf_filter);
        }
    }

    /* Find initial node */
    af_packet_node = ConfGetNode("af-packet");
    if (af_packet_node == NULL) {
        SCLogInfo("unable to find af-packet config using default values");
        goto finalize;
    }

    if_root = ConfFindDeviceConfig(af_packet_node, iface);
    if_default = ConfFindDeviceConfig(af_packet_node, "default");

    if (if_root == NULL && if_default == NULL) {
        SCLogInfo("unable to find af-packet config for "
                  "interface \"%s\" or \"default\", using default values",
                  iface);
        goto finalize;
    }

    /* If there is no setting for current interface use default one as main iface */
    if (if_root == NULL) {
        if_root = if_default;
        if_default = NULL;
    }

    if (active_runmode && !strcmp("single", active_runmode)) {
        aconf->threads = 1;
    } else if (ConfGetChildValueWithDefault(if_root, if_default, "threads", &threadsstr) != 1) {
        aconf->threads = 0;
    } else {
        if (threadsstr != NULL) {
            if (strcmp(threadsstr, "auto") == 0) {
                aconf->threads = 0;
            } else {
                if (StringParseInt32(&aconf->threads, 10, 0, (const char *)threadsstr) < 0) {
                    SCLogWarning(SC_ERR_INVALID_VALUE, "Invalid number of "
                                                       "threads, resetting to default");
                    aconf->threads = 0;
                }
            }
        }
    }

    if (ConfGetChildValueWithDefault(if_root, if_default, "copy-iface", &out_iface) == 1) {
        if (strlen(out_iface) > 0) {
            aconf->out_iface = out_iface;
        }
    }

    if (ConfGetChildValueBoolWithDefault(if_root, if_default, "use-mmap", (int *)&boolval) == 1) {
        if (!boolval) {
            SCLogConfig("Disabling mmaped capture on iface %s",
                        aconf->iface);
            aconf->flags &= ~(AFP_RING_MODE|AFP_TPACKET_V3);
        }
    }

    if (aconf->flags & AFP_RING_MODE) {
        (void)ConfGetChildValueBoolWithDefault(if_root, if_default,
                                               "mmap-locked", (int *)&boolval);
        if (boolval) {
            SCLogConfig("Enabling locked memory for mmap on iface %s",
                        aconf->iface);
            aconf->flags |= AFP_MMAP_LOCKED;
        }

        if (ConfGetChildValueBoolWithDefault(if_root, if_default,
                                             "tpacket-v3", (int *)&boolval) == 1)
        {
            if (boolval) {
                if (strcasecmp(RunmodeGetActive(), "workers") == 0) {
#ifdef HAVE_TPACKET_V3
                    SCLogConfig("Enabling tpacket v3 capture on iface %s",
                                aconf->iface);
                    aconf->flags |= AFP_TPACKET_V3;
#else
                    SCLogNotice("System too old for tpacket v3 switching to v2");
                    aconf->flags &= ~AFP_TPACKET_V3;
#endif
                } else {
                    SCLogWarning(SC_ERR_RUNMODE,
                                 "tpacket v3 is only implemented for 'workers' runmode."
                                 " Switching to tpacket v2.");
                    aconf->flags &= ~AFP_TPACKET_V3;
                }
            } else {
                aconf->flags &= ~AFP_TPACKET_V3;
            }
        }

        (void)ConfGetChildValueBoolWithDefault(if_root, if_default,
                                               "use-emergency-flush", (int *)&boolval);
        if (boolval) {
            SCLogConfig("Enabling ring emergency flush on iface %s",
                        aconf->iface);
            aconf->flags |= AFP_EMERGENCY_MODE;
        }
    }

    aconf->copy_mode = AFP_COPY_MODE_NONE;
    if (ConfGetChildValueWithDefault(if_root, if_default, "copy-mode", &copymodestr) == 1) {
        if (aconf->out_iface == NULL) {
            SCLogInfo("Copy mode activated but no destination"
                      " iface. Disabling feature");
        } else if (!(aconf->flags & AFP_RING_MODE)) {
            SCLogInfo("Copy mode activated but use-mmap "
                      "set to no. Disabling feature");
        } else if (strlen(copymodestr) <= 0) {
            aconf->out_iface = NULL;
        } else if (strcmp(copymodestr, "tap") == 0) {
            SCLogInfo("AF_PACKET TAP mode activated %s->%s",
                      iface,
                      aconf->out_iface);
            aconf->copy_mode = AFP_COPY_MODE_TAP;
            if (aconf->flags & AFP_TPACKET_V3) {
                SCLogWarning(SC_ERR_RUNMODE, "Using tpacket_v3 in TAP mode will result in high latency");
            }
        } else {
            SCLogInfo("Invalid mode (not in tap, ips)");
        }
    }

    aconf->cluster_id = (uint16_t)(cluster_id_auto++);
    /*if (ConfGetChildValueWithDefault(if_root, if_default, "cluster-id", &tmpclusterid) != 1) {
        aconf->cluster_id = (uint16_t)(cluster_id_auto++);
    } else {
        if (StringParseUint16(&aconf->cluster_id, 10, 0, (const char *)tmpclusterid) < 0) {
            SCLogWarning(SC_ERR_INVALID_VALUE, "Invalid cluster_id, resetting to 0");
            aconf->cluster_id = 0;
        }
        SCLogDebug("Going to use cluster-id %" PRIu16, aconf->cluster_id);
    }*/

    if (ConfGetChildValueWithDefault(if_root, if_default, "cluster-type", &tmpctype) != 1) {
        /* default to our safest choice: flow hashing + defrag enabled */
        aconf->cluster_type = PACKET_FANOUT_HASH | PACKET_FANOUT_FLAG_DEFRAG;
        cluster_type = PACKET_FANOUT_HASH;
    } else if (strcmp(tmpctype, "cluster_round_robin") == 0) {
        SCLogConfig("Using round-robin cluster mode for AF_PACKET (iface %s)",
                    aconf->iface);
        aconf->cluster_type = PACKET_FANOUT_LB;
        cluster_type = PACKET_FANOUT_LB;
    } else if (strcmp(tmpctype, "cluster_flow") == 0) {
        /* In hash mode, we also ask for defragmentation needed to
         * compute the hash */
        uint16_t defrag = 0;
        int conf_val = 0;
        SCLogConfig("Using flow cluster mode for AF_PACKET (iface %s)",
                    aconf->iface);
        ConfGetChildValueBoolWithDefault(if_root, if_default, "defrag", &conf_val);
        if (conf_val) {
            SCLogConfig("Using defrag kernel functionality for AF_PACKET (iface %s)",
                        aconf->iface);
            defrag = PACKET_FANOUT_FLAG_DEFRAG;
        }
        aconf->cluster_type = PACKET_FANOUT_HASH | defrag;
        cluster_type = PACKET_FANOUT_HASH;
    } else if (strcmp(tmpctype, "cluster_cpu") == 0) {
        SCLogConfig("Using cpu cluster mode for AF_PACKET (iface %s)",
                    aconf->iface);
        aconf->cluster_type = PACKET_FANOUT_CPU;
        cluster_type = PACKET_FANOUT_CPU;
    } else if (strcmp(tmpctype, "cluster_qm") == 0) {
        SCLogConfig("Using queue based cluster mode for AF_PACKET (iface %s)",
                    aconf->iface);
        aconf->cluster_type = PACKET_FANOUT_QM;
        cluster_type = PACKET_FANOUT_QM;
    } else if (strcmp(tmpctype, "cluster_random") == 0) {
        SCLogConfig("Using random based cluster mode for AF_PACKET (iface %s)",
                    aconf->iface);
        aconf->cluster_type = PACKET_FANOUT_RND;
        cluster_type = PACKET_FANOUT_RND;
    } else if (strcmp(tmpctype, "cluster_rollover") == 0) {
        SCLogConfig("Using rollover based cluster mode for AF_PACKET (iface %s)",
                    aconf->iface);
        SCLogWarning(SC_WARN_UNCOMMON, "Rollover mode is causing severe flow "
                                       "tracking issues, use it at your own risk.");
        aconf->cluster_type = PACKET_FANOUT_ROLLOVER;
        cluster_type = PACKET_FANOUT_ROLLOVER;
    } else {
        SCLogWarning(SC_ERR_INVALID_CLUSTER_TYPE,"invalid cluster-type %s",tmpctype);
    }

    int conf_val = 0;
    ConfGetChildValueBoolWithDefault(if_root, if_default, "rollover", &conf_val);
    if (conf_val) {
        SCLogConfig("Using rollover kernel functionality for AF_PACKET (iface %s)",
                    aconf->iface);
        aconf->cluster_type |= PACKET_FANOUT_FLAG_ROLLOVER;
        SCLogWarning(SC_WARN_UNCOMMON, "Rollover option is causing severe flow "
                                       "tracking issues, use it at your own risk.");
    }

    /*load af_packet bpf filter*/
    /* command line value has precedence */
    if (ConfGet("bpf-filter", &bpf_filter) != 1) {
        if (ConfGetChildValueWithDefault(if_root, if_default, "bpf-filter", &bpf_filter) == 1) {
            if (strlen(bpf_filter) > 0) {
                aconf->bpf_filter = bpf_filter;
                SCLogConfig("Going to use bpf filter %s", aconf->bpf_filter);
            }
        }
    }

    if ((ConfGetChildValueIntWithDefault(if_root, if_default, "buffer-size", &value)) == 1) {
        aconf->buffer_size = value;
    } else {
        aconf->buffer_size = 0;
    }
    if ((ConfGetChildValueIntWithDefault(if_root, if_default, "ring-size", &value)) == 1) {
        aconf->ring_size = value;
    }

    if ((ConfGetChildValueIntWithDefault(if_root, if_default, "block-size", &value)) == 1) {
        if (value % getpagesize()) {
            SCLogError(SC_ERR_INVALID_VALUE, "Block-size must be a multiple of pagesize.");
        } else {
            aconf->block_size = value;
        }
    }

    if ((ConfGetChildValueIntWithDefault(if_root, if_default, "block-timeout", &value)) == 1) {
        aconf->block_timeout = value;
    } else {
        aconf->block_timeout = 10;
    }

    (void)ConfGetChildValueBoolWithDefault(if_root, if_default, "disable-promisc", (int *)&boolval);
    if (boolval) {
        SCLogConfig("Disabling promiscuous mode on iface %s",
                    aconf->iface);
        aconf->promisc = 0;
    }

    if (ConfGetChildValueWithDefault(if_root, if_default, "checksum-checks", &tmpctype) == 1) {
        if (strcmp(tmpctype, "auto") == 0) {
            aconf->checksum_mode = CHECKSUM_VALIDATION_AUTO;
        } else if (ConfValIsTrue(tmpctype)) {
            aconf->checksum_mode = CHECKSUM_VALIDATION_ENABLE;
        } else if (ConfValIsFalse(tmpctype)) {
            aconf->checksum_mode = CHECKSUM_VALIDATION_DISABLE;
        } else if (strcmp(tmpctype, "kernel") == 0) {
            aconf->checksum_mode = CHECKSUM_VALIDATION_KERNEL;
        } else {
            SCLogError(SC_ERR_INVALID_ARGUMENT, "Invalid value for checksum-checks for %s", aconf->iface);
        }
    }

finalize:

    /* if the number of threads is not 1, we need to first check if fanout
     * functions on this system. */
    if (aconf->threads != 1) {
        if (AFPIsFanoutSupported(aconf->cluster_id) == 0) {
            if (aconf->threads != 0) {
                SCLogNotice("fanout not supported on this system, falling "
                            "back to 1 capture thread");
            }
            aconf->threads = 1;
        }
    }

    /* try to automagically set the proper number of threads */
    //comment by haolipeng
    /*if (aconf->threads == 0) {
        *//* for cluster_flow use core count *//*
        if (cluster_type == PACKET_FANOUT_HASH) {
            aconf->threads = (int)UtilCpuGetNumProcessorsOnline();
            SCLogPerf("%u cores, so using %u threads", aconf->threads, aconf->threads);

            *//* for cluster_qm use RSS queue count *//*
        } else if (cluster_type == PACKET_FANOUT_QM) {
            int rss_queues = GetIfaceRSSQueuesNum(iface);
            if (rss_queues > 0) {
                aconf->threads = rss_queues;
                SCLogPerf("%d RSS queues, so using %u threads", rss_queues, aconf->threads);
            }
        }

        if (aconf->threads) {
            SCLogPerf("Using %d AF_PACKET threads for interface %s",
                      aconf->threads, iface);
        }
    }*/
    if (aconf->threads <= 0) {
        aconf->threads = 1;
    }
    SC_ATOMIC_RESET(aconf->ref);
    (void) SC_ATOMIC_ADD(aconf->ref, aconf->threads);

    if (aconf->ring_size != 0) {
        if (aconf->ring_size * aconf->threads < max_pending_packets) {
            aconf->ring_size = max_pending_packets / aconf->threads + 1;
            SCLogWarning(SC_ERR_AFP_CREATE, "Inefficient setup: ring-size < max_pending_packets. "
                                            "Resetting to decent value %d.", aconf->ring_size);
            /* We want at least that max_pending_packets packets can be handled by the
             * interface. This is generous if we have multiple interfaces listening. */
        }
    } else {
        /* We want that max_pending_packets packets can be handled by suricata
         * for this interface. To take burst into account we multiply the obtained
         * size by 2. */
        aconf->ring_size = max_pending_packets * 2 / aconf->threads;
    }

    int ltype = AFPGetLinkType(iface);
    switch (ltype) {
        case LINKTYPE_ETHERNET:
            /* af-packet can handle csum offloading */
            /*if (LiveGetOffload() == 0) {
                if (GetIfaceOffloading(iface, 0, 1) == 1) {
                    SCLogWarning(SC_ERR_AFP_CREATE,
                                 "Using AF_PACKET with offloading activated leads to capture problems");
                }
            } else {
                DisableIfaceOffloading(LiveGetDevice(iface), 0, 1);
            }*/
            break;
        case -1:
        default:
            break;
    }

    if (active_runmode && !strcmp("workers", active_runmode)) {
        aconf->flags |= AFP_ZERO_COPY;
    } else {
        /* If we are using copy mode we need a lock */
        aconf->flags |= AFP_SOCK_PROTECT;
    }

    /* If we are in RING mode, then we can use ZERO copy
     * by using the data release mechanism */
    if (aconf->flags & AFP_RING_MODE) {
        aconf->flags |= AFP_ZERO_COPY;
    }

    if (aconf->flags & AFP_ZERO_COPY) {
        SCLogConfig("%s: enabling zero copy mode by using data release call", iface);
    }

    return aconf;
}


int RunModeSetLiveCaptureSingle(ConfigIfaceParserFunc ConfigParser,const char *recv_mod_name,
                                const char *decode_mod_name, const char *thread_name,
                                const char *live_dev)
{
    void *aconf = NULL;
    const char *live_dev_c = NULL;

    if (live_dev != NULL) {
        aconf = ConfigParser(live_dev);
        live_dev_c = live_dev;
    }

    return RunModeSetLiveCaptureWorkersForDevice(
            recv_mod_name,
            decode_mod_name,
            thread_name,
            live_dev_c,
            aconf,
            1);
}

int RunModeIdsAFPSingle(void)
{
    int ret;
    const char *live_dev = NULL;

    //RunModeInitialize();
    TimeModeSetLive();

    extern char* g_in_iface;
    (void)ConfGet("af-packet.live-interface", &live_dev);
    if(NULL == live_dev){
        live_dev = g_in_iface;
    }

    if (AFPPeersListInit() != TM_ECODE_OK) {
        FatalError(SC_ERR_FATAL, "Unable to init peers list.");
    }

    const char *thread_name_single = "W";
    ret = RunModeSetLiveCaptureSingle(ParseAFPConfig,
                                      "ReceiveAFP",
                                      "DecodeAFP", thread_name_single,
                                      live_dev);
    if (ret != 0) {
        FatalError(SC_ERR_FATAL, "Unable to start runmode");
    }

    SCLogDebug("RunModeIdsAFPSingle initialised");

    return (0);
}

void RunModeIdsAFPRegister(void)
{
    RunModeRegisterNewRunMode(RUNMODE_AFP_DEV, "single",
                              "Single threaded af-packet mode",
                              RunModeIdsAFPSingle);

    return;
}