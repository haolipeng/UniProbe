一、依赖库
no

二、网络流量捕获
    1.windows
        winpcap
        npcap

    2.linux
        pcap file
        AF_PACKET + MMAP

三、线程模型
agent端资源有限，所以采用run to complete线程模型

四、编程约定
先采用纯C编码，基础组件源于个人base库.业务逻辑需要的基础组件持续更新。

五、测试

在项目中引入gtest,从代码级别写代码进行测试

六、TODO事项

VxLan协议的解析没有实现协议识别和解析，以及展示相应字段

线程级别的ipv4、ipv6、tcp、udp、icmp数据包的个数，暂时未实现,multiple thread result merge to one thread  

StatsIncr comment
StatsAddUI64 comment