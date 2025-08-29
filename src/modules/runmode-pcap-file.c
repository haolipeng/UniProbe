#include <stdio.h>

#include "runmode-pcap-file.h"
#include "runmodes.h"
#include "modules/tm-threads.h"
#include "modules/tm-modules.h"
#include "utils/conf.h"
#include "source-pcap-file.h"
#include "utils/util-time.h"

const char *RunModeFilePcapGetDefaultMode(void)
{
    return "autofp";
}

void RunModeFilePcapRegister(void)
{
    //only register single pcap file mode
    RunModeRegisterNewRunMode(RUNMODE_PCAP_FILE, "single",
                              "Single threaded pcap file mode",
                              RunModeFilePcapSingle);

    return;
}

/**
 * \brief Single thread version of the Pcap file processing.
 */
int RunModeFilePcapSingle(void)
{
    const char *file = NULL;
    char tname[TM_THREAD_NAME_MAX];
    if (ConfGet("pcap-file.file", &file) == 0) {
        FatalError(SC_ERR_FATAL, "Failed retrieving pcap-file from Conf");
    }

    TimeModeSetOffline();
    PcapFileGlobalInit();

    const char *thread_name_single = "W";
    snprintf(tname, sizeof(tname), "%s#01", thread_name_single);

    /* create the threads */
    ThreadVars *tv = TmThreadCreatePacketHandler(tname,
                                                 "packetpool", "packetpool",
                                                 "packetpool", "packetpool",
                                                 "pktacqloop");
    if (tv == NULL) {
        FatalError(SC_ERR_FATAL, "threading setup failed");
    }

    TmModule *tm_module = TmModuleGetByName("ReceivePcapFile");
    if (tm_module == NULL) {
        FatalError(SC_ERR_FATAL, "TmModuleGetByName failed for ReceivePcap");
    }
    TmSlotSetFuncAppend(tv, tm_module, file);

    tm_module = TmModuleGetByName("DecodePcapFile");
    if (tm_module == NULL) {
        FatalError(SC_ERR_FATAL, "TmModuleGetByName DecodePcap failed");
    }
    TmSlotSetFuncAppend(tv, tm_module, NULL);

    tm_module = TmModuleGetByName("FlowWorker");
    if (tm_module == NULL) {
        FatalError(SC_ERR_FATAL, "TmModuleGetByName for FlowWorker failed");
    }
    TmSlotSetFuncAppend(tv, tm_module, NULL);

    if (TmThreadSpawn(tv) != TM_ECODE_OK) {
        FatalError(SC_ERR_FATAL, "TmThreadSpawn failed");
    }
    return 0;
}
