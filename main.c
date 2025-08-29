#include <unistd.h>
#include <strings.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <sys/time.h>
#include <bits/types/sig_atomic_t.h>
#include <sys/stat.h>
#include <signal.h>

#include "base.h"
#include "utils/conf-yaml-loader.h"
#include "modules/runmodes.h"
#include "modules/source-af-packet.h"
#include "modules/tm-modules.h"
#include "modules/tm-queuehandlers.h"
#include "flow/flow-manager.h"
#include "flow/flow-worker.h"
#include "utils/conf.h"
#include "utils/util-device.h"
#include "dpi/main.h"
#include "reassemble/stream-tcp.h"
#include "utils/util-misc.h"
#include "modules/source-pcap-file.h"
#include "utils/util-ioctl.h"
#include "output/output.h"
#include "utils/util-signal.h"

#define DEFAULT_CONF_FILE "/etc/suricata/suricata.yaml"
#define DEFAULT_MAX_PENDING_PACKETS 1024
intmax_t max_pending_packets = DEFAULT_MAX_PENDING_PACKETS;

////////////////////////////全局变量区//////////////////////////////
char *g_pcap_path = NULL;
char* g_in_iface;
char* g_virtual_iface;
int g_threads = 1; //one capture thread per nic = 1

__thread int THREAD_ID;

int g_default_mtu = 0;

#define DEFAULT_MTU 1500

/////////////////////////////////////////////////////////////////
volatile sig_atomic_t sigint_count = 0;
volatile sig_atomic_t sighup_count = 0;
volatile sig_atomic_t sigterm_count = 0;
volatile sig_atomic_t sigusr2_count = 0;

/*
 * Flag to indicate if the engine is at the initialization
 * or already processing packets. 3 stages: SURICATA_INIT,
 * SURICATA_RUNTIME and SURICATA_FINALIZE
 */
SC_ATOMIC_DECLARE(unsigned int, engine_stage);

/** suricata engine control flags */
volatile uint8_t suricata_ctl_flags = 0;

/** Suricata instance */
SCInstance suricata;

static void SCInstanceInit(SCInstance *suri, const char *progname)
{
    memset(suri, 0x00, sizeof(*suri));

    suri->progname = progname;
    suri->run_mode = RUNMODE_UNKNOWN;

    memset(suri->pcap_dev, 0, sizeof(suri->pcap_dev));
    suri->sig_file = NULL;
    suri->sig_file_exclusive = FALSE;
    suri->pid_filename = NULL;
    suri->regex_arg = NULL;

    suri->keyword_info = NULL;
    suri->runmode_custom_mode = NULL;

    suri->delayed_detect = 0;
    suri->daemon = 0;
    suri->offline = 0;
    suri->verbose = 0;
    /* use -1 as unknown */
    suri->checksum_validation = -1;
}

static int ParseCommandLineAfpacket(SCInstance *suri, const char *in_arg)
{
  if (suri->run_mode == RUNMODE_UNKNOWN) {
      suri->run_mode = RUNMODE_AFP_DEV;
      if (in_arg) {
          LiveRegisterDeviceName(in_arg);
          memset(suri->pcap_dev, 0, sizeof(suri->pcap_dev));
          strlcpy(suri->pcap_dev, in_arg, sizeof(suri->pcap_dev));
      }
  } else if (suri->run_mode == RUNMODE_AFP_DEV) {
      if (in_arg) {
          LiveRegisterDeviceName(in_arg);
      } else {
          SCLogInfo("Multiple af-packet option without interface on each is useless");
      }
  } else {
    SCLogError(SC_ERR_MULTIPLE_RUN_MODE, "more than one run mode has been specified");
    return TM_ECODE_FAILED;
  }
  return TM_ECODE_OK;
}

//解析程序命令行参数
static int ParseCommandLine(int argc, char **argv,SCInstance *suri){
    int arg = 0;

    while (arg != -1) {
        arg = getopt(argc, argv, "h:i:v:c:j:r:");

        switch (arg) {
            case -1:
                break;
            case 'i':
                if(NULL == optarg){
                    SCLogError(SC_ERR_INITIALIZATION, "no option argument for -i");
                    return TM_ECODE_FAILED;
                }
                g_in_iface = strdup(optarg);//设置网口
                if (ParseCommandLineAfpacket(&suricata, g_in_iface) != TM_ECODE_OK) {
                    SCLogError(SC_ERR_INITIALIZATION, "parse af-packet for -i interface failed!");
                    return TM_ECODE_FAILED;
                }
                break;
            case 'c':
                suricata.conf_filename = strdup(optarg);
                break;
            case 'v':
                g_virtual_iface = strdup(optarg);
                break;
            case 'r':
                if (suri->run_mode == RUNMODE_UNKNOWN) {
                    suri->run_mode = RUNMODE_PCAP_FILE;
                } else {
                    SCLogError(SC_ERR_MULTIPLE_RUN_MODE, "more than one run mode has been specified");
                    return TM_ECODE_FAILED;
                }
                g_pcap_path = optarg;

                struct stat buf;
                if (stat(optarg, &buf) != 0) {
                    SCLogError(SC_ERR_INITIALIZATION, "ERROR: Pcap file does not exist\n");
                    return TM_ECODE_FAILED;
                }
                if (ConfSetFinal("pcap-file.file", optarg) != 1) {
                    SCLogError(SC_ERR_INITIALIZATION, "ERROR: Failed to set pcap-file.file\n");
                    return TM_ECODE_FAILED;
                }

                break;
            case 'h':
            default:
                exit(-2);
        }
    }

    /* save the runmode from the commandline (if any) */
    suri->aux_run_mode = suri->run_mode;

    return TM_ECODE_OK;
}

void RegisterAllModules(void)
{
    // zero all module storage
    memset(tmm_modules, 0, TMM_SIZE * sizeof(TmModule));

    /* managers */
    TmModuleFlowManagerRegister();
    TmModuleFlowRecyclerRegister();

    /* pcap file */
    TmModuleReceivePcapFileRegister();
    TmModuleDecodePcapFileRegister();

    /* af-packet */
    TmModuleReceiveAFPRegister();
    TmModuleDecodeAFPRegister();

    /* flow worker */
    TmModuleFlowWorkerRegister();

    /* log api */
    TmModuleLoggerRegister();
}

int InitGlobal(void){
    //1.初始化engine state
    SC_ATOMIC_INIT(engine_stage);

    //2.初始化日志系统
    SCLogInitLogModule(NULL);

    //3.初始化util-misc
    ParseSizeInit();

    //4.Register runmodes
    RunModeRegisterRunModes();

    //5.初始化Config系统
    ConfInit();
    return 0;
}

static TmEcode LoadYamlConfig(SCInstance *suri)
{
    if (suri->conf_filename == NULL)
        suri->conf_filename = DEFAULT_CONF_FILE;

    if (ConfYamlLoadFile(suri->conf_filename) != 0) {
        /* Error already displayed. */
        return (TM_ECODE_FAILED);
    }

    return (TM_ECODE_OK);
}

static TmEcode ParseInterfacesList(const int runmode, char *pcap_dev)
{
    /* run the selected runmode */
    if (runmode == RUNMODE_AFP_DEV) {
        /* iface has been set on command line */
        if (strlen(pcap_dev)) {
            if (ConfSetFinal("af-packet.live-interface", pcap_dev) != 1) {
                SCLogError(SC_ERR_INITIALIZATION, "Failed to set af-packet.live-interface");
                return (TM_ECODE_FAILED);
            }
        } else {
            int ret = LiveBuildDeviceList("af-packet");
            if (ret == 0) {
                SCLogError(SC_ERR_INITIALIZATION, "No interface found in config for af-packet");
                return (TM_ECODE_FAILED);
            }
        }
    }

    return (TM_ECODE_OK);
}

static int ConfigGetCaptureValue(SCInstance *suri)
{
    /* Pull the max pending packets from the config, if not found fall
     * back on a sane default. */
    if (ConfGetInt("max-pending-packets", &max_pending_packets) != 1)
        max_pending_packets = DEFAULT_MAX_PENDING_PACKETS;
    if (max_pending_packets >= 65535) {
        SCLogError(SC_ERR_INVALID_YAML_CONF_ENTRY,
                   "Maximum max-pending-packets setting is 65534. "
                   "Please check %s for errors", suri->conf_filename);
        return TM_ECODE_FAILED;
    }

    SCLogDebug("Max pending packets set to %"PRIiMAX, max_pending_packets);

    /* Pull the default packet size from the config, if not found fall
     * back on a sane default. */
    const char *temp_default_packet_size;
    if ((ConfGet("default-packet-size", &temp_default_packet_size)) != 1) {
        int mtu = 0;
        int lthread;
        int nlive;
        int strip_trailing_plus = 0;
        switch (suri->run_mode) {
            case RUNMODE_PCAP_DEV:
            case RUNMODE_AFP_DEV:
                nlive = LiveGetDeviceNameCount();
                for (lthread = 0; lthread < nlive; lthread++) {
                    const char *live_dev = LiveGetDeviceNameName(lthread);
                    char dev[128]; /* need to be able to support GUID names on Windows */
                    (void)strlcpy(dev, live_dev, sizeof(dev));

                    if (strip_trailing_plus) {
                        size_t len = strlen(dev);
                        if (len &&
                            (dev[len-1] == '+' ||
                             dev[len-1] == '^' ||
                             dev[len-1] == '*'))
                        {
                            dev[len-1] = '\0';
                        }
                    }
                    mtu = GetIfaceMTU(dev);
                    g_default_mtu = MAX(mtu, g_default_mtu);

                    unsigned int iface_max_packet_size = GetIfaceMaxPacketSize(dev);
                    if (iface_max_packet_size > default_packet_size)
                        default_packet_size = iface_max_packet_size;
                }
                if (default_packet_size)
                    break;
                /* fall through */
            default:
                g_default_mtu = DEFAULT_MTU;
                default_packet_size = DEFAULT_PACKET_SIZE;
        }
    } else {
        if (ParseSizeStringU32(temp_default_packet_size, &default_packet_size) < 0) {
            SCLogError(SC_ERR_SIZE_PARSE, "Error parsing max-pending-packets "
                                          "from conf file - %s.  Killing engine",
                       temp_default_packet_size);
            return TM_ECODE_FAILED;
        }
    }

    SCLogDebug("Default packet size set to %"PRIu32, default_packet_size);

    return TM_ECODE_OK;
}

static void SignalHandlerSigint(/*@unused@*/ int sig)
{
    sigint_count = 1;
}
static void SignalHandlerSigterm(/*@unused@*/ int sig)
{
    sigterm_count = 1;
}

/**
 * SIGHUP handler.  Just set sighup_count.  The main loop will act on
 * it.
 */
static void SignalHandlerSigHup(/*@unused@*/ int sig)
{
    sighup_count = 1;
}

static int InitSignalHandler(){
    UtilSignalHandlerSetup(SIGINT, SignalHandlerSigint);
    UtilSignalHandlerSetup(SIGTERM, SignalHandlerSigterm);

    UtilSignalHandlerSetup(SIGHUP, SignalHandlerSigHup);

    return TM_ECODE_OK;
}

void PreRunInit(const int runmode)
{
    //TODO:modify by haolipeng
    //DefragInit();
    FlowInitConfig(FLOW_QUIET);
    StreamTcpInitConfig(STREAM_VERBOSE);
}

void PreRunPostPrivsDropInit(const int runmode)
{
    RunModeInitializeOutputs();
}

int PostConfLoadedSetup(SCInstance *suri)
{
    //TODO:load the pattern matchers

    //Get custom runmode
    if (suri->runmode_custom_mode) {
        ConfSet("runmode", suri->runmode_custom_mode);
    }

    //TODO:load capture setting
    if (ConfigGetCaptureValue(suri) != TM_ECODE_OK) {
        return (TM_ECODE_FAILED);
    }

    //thread modules queue handler setup
    TmqhSetup();

    //TODO:register all modules
    RegisterAllModules();

    //TODO:Module Run Init function
    TmModuleRunInit();

    //TODO:need to add signal handler
    if (InitSignalHandler(suri) != TM_ECODE_OK)
        return TM_ECODE_FAILED;

    if(suri->disabled_detect){
        SCLogConfig("dectection engine disabled");
        (void)ConfSetFinal("stream.reassembly.raw", "false");
    }

    LiveDeviceFinalize();

    PreRunInit(suri->run_mode);

    return TM_ECODE_OK;
}

static void SCSetStartTime(SCInstance *suri)
{
    memset(&suri->start_time, 0, sizeof(suri->start_time));
    gettimeofday(&suri->start_time, NULL);
}

static void SuricataMainLoop(SCInstance *suri)
{
    while(1) {
        if (sigterm_count || sigint_count) {
            suricata_ctl_flags |= SURICATA_STOP;
        }

        if (suricata_ctl_flags & SURICATA_STOP) {
            SCLogNotice("Signal Received.  Stopping engine.");
            break;
        }

        TmThreadCheckThreadState();

        if (sighup_count > 0) {
            sighup_count--;
        }

        usleep(10* 1000);
    }
}

void EngineDone(void)
{
    suricata_ctl_flags |= SURICATA_DONE;
}

void EngineStop(void)
{
    suricata_ctl_flags |= SURICATA_STOP;
}

int main(int argc, char *argv[])
{
    int ret = 0;
    //1.Instance init
    SCInstanceInit(&suricata, argv[0]);

    //2.Global init
    ret = InitGlobal();
    if(ret != 0){
        exit(EXIT_FAILURE);
    }

    //3.解析程序命令行参数
    ParseCommandLine(argc, argv, &suricata);

    //4.Load yaml configuration file if provided.
    if (LoadYamlConfig(&suricata) != TM_ECODE_OK) {
        exit(EXIT_FAILURE);
    }

    //5.Parser Interface
    if (ParseInterfacesList(suricata.aux_run_mode, suricata.pcap_dev) != TM_ECODE_OK) {
        exit(EXIT_FAILURE);
    }

    if (PostConfLoadedSetup(&suricata) != TM_ECODE_OK) {
        exit(EXIT_FAILURE);
    }

    SCSetStartTime(&suricata);

    RunModeDispatch(suricata.run_mode, suricata.runmode_custom_mode);

    if (TmThreadWaitOnThreadInit() == TM_ECODE_FAILED) {
        FatalError(SC_ERR_FATAL, "Engine initialization failed, "
                                 "aborting...");
    }

    SC_ATOMIC_SET(engine_stage, SURICATA_RUNTIME);

    /* Un-pause all the paused threads */
    TmThreadContinueThreads();

    SuricataMainLoop(&suricata);

    /* Update the engine stage/status flag */
    SC_ATOMIC_SET(engine_stage, SURICATA_DEINIT);

    printf("program is almost shutdown");
    return ret;
}