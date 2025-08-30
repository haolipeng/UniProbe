cmake_minimum_required(VERSION 3.16)
project(net_threat_detect C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_BUILD_TYPE "debug")

#
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g -O0 -Wall -Werror -Wno-unused-result -Wno-unused-function -fstrict-aliasing -Wstrict-aliasing")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_Release} -g -O0 -Wall -Werror -Wno-unused-result -Wno-unused-function -fstrict-aliasing -Wstrict-aliasing")

include_directories(./src)
include_directories(third-party/include)
include_directories("/usr/local/include")

link_directories(third-party/lib)
link_directories("/usr/local/lib")

add_executable(net_threat_detect
        main.c
        src/base.h

        /*common*/
        src/common/address-port.h  src/common/packet-define.h
        src/common/autoconf.h
        src/common/common.h

        /*reassemble*/
        src/reassemble/stream.h src/reassemble/tree.h
        src/reassemble/stream-tcp.h src/reassemble/stream-tcp.c
        src/reassemble/stream-tcp-private.h
        src/reassemble/stream-tcp-list.c
        src/reassemble/streaming-buffer.h src/reassemble/streaming-buffer.c
        src/reassemble/stream-tcp-reassemble.h src/reassemble/stream-tcp-reassemble.c
        src/reassemble/stream-tcp-inline.h src/reassemble/stream-tcp-inline.c
        src/reassemble/stream-tcp-sack.h src/reassemble/stream-tcp-sack.c

        /*decode*/
        src/decode/decode-ethernet.c src/decode/decode-ethernet.h
        src/decode/decode-ipv4.c src/decode/decode-ipv4.h
        src/decode/decode-ipv6.c src/decode/decode-ipv6.h
        src/decode/decode-tcp.c src/decode/decode-tcp.h
        src/decode/decode-udp.c src/decode/decode-udp.h
        src/decode/decode.c src/decode/decode.h
        src/decode/decode-thread-var.h src/decode/decode-thread-var.c
        src/decode/decode-events.h src/decode/decode-vlan.h

        /*utils*/
        src/utils/helper.h
        src/utils/bits.h
        src/utils/util-debug.h src/utils/util-debug.c
        src/utils/util-error.h src/utils/util-error.c
        src/utils/util-enum.h src/utils/util-enum.c
        src/utils/util-atomic.h src/utils/util-atomic.c
        src/utils/util-random.h src/utils/util-random.c
        src/utils/util-misc.h src/utils/util-misc.c
        src/utils/util-byte.h src/utils/util-byte.c
        src/utils/conf.h src/utils/conf.c
        src/utils/util-pool-thread.h src/utils/util-pool-thread.c
        src/utils/util-pool.h src/utils/util-pool.c
        src/utils/util-time.h src/utils/util-time.c
        src/utils/util-hash-lookup3.h src/utils/util-hash-lookup3.c
        src/utils/util-path.c src/utils/util-path.h
        src/utils/util-conf.h src/utils/util-conf.c
        src/utils/util-device.h src/utils/util-device.c
        src/utils/util-strlcatu.h src/utils/util-strlcatu.c
        src/utils/util-exception-policy.h src/utils/util-exception-policy.c
        src/utils/util-ioctl.h src/utils/util-ioctl.c
        src/utils/util-optimize.h src/utils/util-mem.h
        src/utils/packet-queue.h src/utils/packet-queue.c
        src/utils/conf-yaml-loader.c src/utils/conf-yaml-loader.h
        src/utils/util-print.h src/utils/util-print.c
        src/utils/util-signal.h src/utils/util-signal.c
        src/utils/queue.h src/utils/threads.h

        /*flow*/
        src/flow/flow-manager.h src/flow/flow-manager.c
        src/flow/flow-queue.h src/flow/flow-queue.c
        src/flow/flow-timeout.h src/flow/flow-timeout.c
        src/flow/flow.h src/flow/flow.c
        src/flow/flow-spare-pool.h src/flow/flow-spare-pool.c
        src/flow/flow-util.h src/flow/flow-util.c
        src/flow/flow-hash.h src/flow/flow-hash.c
        src/flow/flow-worker.h src/flow/flow-worker.c

        /*app-layer*/
        src/app-layer/app-layer-events.h src/app-layer/app-layer-events.c
        src/app-layer/app-layer-parser.h src/app-layer/app-layer-parser.c

        /*detect*/
        src/detect/detect.h

        /*dpi*/
        src/main.h

        /*modules*/
        src/modules/tmqh-packetpool.h src/modules/tmqh-packetpool.c

        src/modules/threadvars.h

        src/modules/tm-threads.h src/modules/tm-threads.c
        src/modules/tm-queues.h src/modules/tm-queues.c
        src/modules/tm-queuehandlers.h src/modules/tm-queuehandlers.c
        src/modules/source-af-packet.h src/modules/source-af-packet.c
        src/modules/tm-modules.h src/modules/tm-modules.c
        src/modules/tm-threads-common.h
        src/modules/runmode-af-packet.h src/modules/runmode-af-packet.c
        src/modules/runmodes.c src/modules/runmodes.h
        src/modules/runmode-pcap-file.h src/modules/runmode-pcap-file.c
        src/modules/source-pcap-file.h src/modules/source-pcap-file.c
        src/modules/source-pcap-file-helper.h src/modules/source-pcap-file-helper.c
        src/modules/source-pcap-file-directory-helper.h src/modules/source-pcap-file-directory-helper.c
        src/output/output.h src/output/output.c src/output/output-flow.h src/output/output-flow.c
        src/output/output-json.h src/output/output-json.c
        src/utils/util-logopenfile.h src/utils/util-logopenfile.c
        src/output/output-json-flow.h src/output/output-json-flow.c
        src/utils/util-buffer.h src/utils/util-buffer.c)

target_link_libraries(net_threat_detect
        pthread
        pcap
        pcre
        yaml
        jansson)