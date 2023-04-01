
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet
from ryu.ofproto import ether
from ryu.lib.packet import ethernet, arp, ipv4, tcp
from ryu.lib.packet import ether_types


class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.mac_to_port = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        # install table-miss flow entry
        #
        # We specify NO BUFFER to max_len of the output action due to
        # OVS bug. At this moment, if we specify a lesser number, e.g.,
        # 128, OVS will send Packet-In with invalid buffer_id and
        # truncated packet data. In that case, we cannot output packets
        # correctly.  The bug has been fixed in OVS v2.1.0.
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)

    def _send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        # self.logger.info("packet-out %s" % (pkt,))
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)
        datapath.send_msg(out)

    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only %s of %s bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            # ignore lldp packet
            return

        dst_MAC = eth.dst
        src_MAC = eth.src

        # if ARP request
        if (eth.ethertype == ether_types.ETH_TYPE_ARP):
            arpPKT = pkt.get_protocol(arp.arp)
            # if this is a request then opcode is 1 so we must do something
            if arpPKT.opcode == 1:
                arpReqDstIp = arpPKT.dst_ip
                arpReqSrcIp = arpPKT.src_ip
                # We can use this function since we know
                # which host MAC is associated with which IP
                arpReqDstMAC = self.convertIPtoMAC(arpReqDstIp)
                arpReqSrcMAC = self.convertIPtoMAC(arpReqSrcIp)
                # print("[ARP] request arrive at ", datapath.id, in_port)
                # print("Src IP :{}, Dst IP: {}, sourceMAC : {}, destMAC: {}".format(arpReqSrcIp,arpReqDstIp,arpReqSrcMAC,arpReqDstMAC))
                # print("Replying to the ARP request")
                self.arpReply(msg)
                print("Replied to the ARP request")
        # IF IPv4
        elif (eth.ethertype == ether_types.ETH_TYPE_IP):
            print("Received IPv4 packet in switch {}, port = {}, dstMAC =  {}, srcMAC = {}, ethType = {}".format(
                datapath.id, in_port, dst_MAC, src_MAC, eth.ethertype))
            ipv4_header = pkt.get_protocol(ipv4.ipv4)
            srcIP = ipv4_header.src
            dstIP = ipv4_header.dst
            protoID = ipv4_header.proto
            print("srcIP: {}, dstIP: {}, proto:{}".format(srcIP, dstIP, protoID))
            # If ICMP
            if protoID == 1:
                # ICMP packet
                out_port = self.getNextHopPortICMPorTCP(msg)
                # print("Output Port set to : {}".format(out_port))
                # First let's add the rule to this switch
                # Action is to forward to out_port
                actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
                # Match on, input port, eth dest, ipv4 dest, and ip proto
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst_MAC, eth_type=ether_types.ETH_TYPE_IP,
                                        ipv4_dst=dstIP, ip_proto=protoID)
                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    return
                else:
                    self.add_flow(datapath, 1, match, actions)
                # print("Added new rule to switch:{}, Match: {}, Action: {}".format(
                #     datapath,match,actions))
                # Now send the first packet through the correct port
                out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath,
                                                           buffer_id=msg.buffer_id, in_port=in_port, actions=actions,
                                                           data=pkt)
                datapath.send_msg(out)
            if protoID == 6:
                # TCP packet
                print('TCP Packet')
                tcp_header = pkt.get_protocol(tcp.tcp)
                tcp_dst_port = tcp_header.dst_port
                if tcp_dst_port == 80 and (srcIP == '10.0.0.2' or srcIP == '10.0.0.4'):
                    print('HTTP from {}'.format(srcIP))
                    # self.httpRST(msg)
                    rst_pkt = packet.Packet()
                    e = ethernet.ethernet(ethertype=eth.ethertype, src=dst_MAC, dst=src_MAC)
                    i = ipv4.ipv4(src=ipv4_header.dst, dst=ipv4_header.src, proto=6)
                    t = tcp.tcp(src_port=tcp_header.dst_port, dst_port=tcp_header.src_port, ack=tcp_header.seq + 1,
                                bits=0b010100)
                    rst_pkt.add_protocol(e)
                    rst_pkt.add_protocol(i)
                    rst_pkt.add_protocol(t)
                    self._send_packet(datapath, in_port, rst_pkt)
                else:
                    print('HTTP from {}'.format(srcIP))
                    out_port = self.getNextHopPortICMPorTCP(msg)
                    actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
                    match = parser.OFPMatch(in_port=in_port, eth_dst=dst_MAC, eth_type=ether_types.ETH_TYPE_IP,
                                            ipv4_dst=dstIP, ip_proto=protoID)
                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                        self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                        return
                    else:
                        self.add_flow(datapath, 1, match, actions)
                    out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath,
                                                               buffer_id=msg.buffer_id, in_port=in_port,
                                                               actions=actions, data=pkt)
                    datapath.send_msg(out)

            if protoID == 17:
                # UDP packet
                print('UDP Packet')
                if srcIP == '10.0.0.1' or srcIP == '10.0.0.4':
                    print('UDP from h1 or h2 drop packet.')
                    return
                else:
                    out_port = self.getNextHopPortUDP(msg)
                    actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
                    match = parser.OFPMatch(in_port=in_port, eth_dst=dst_MAC, eth_type=ether_types.ETH_TYPE_IP,
                                            ipv4_dst=dstIP, ip_proto=protoID)
                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                        self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                        return
                    else:
                        self.add_flow(datapath, 1, match, actions)
                    out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath,
                                                               buffer_id=msg.buffer_id, in_port=in_port,
                                                               actions=actions, data=pkt)
                    datapath.send_msg(out)

        else:
            print('Unknow ethertype, not ARP, not IPv4.')

    def getNextHopPortICMPorTCP(self, msg):
        datapath = msg.datapath
        swID = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        ipv4_header = pkt.get_protocol(ipv4.ipv4)
        srcIP = ipv4_header.src
        dstIP = ipv4_header.dst
        srcLastDigit = int(srcIP[-1])
        dstLastDigit = int(dstIP[-1])
        # if we miss everything it will be flood.
        out_port = ofproto.OFPP_FLOOD
        if in_port == 1:
            # print('Packet Coming from port 1')
            # print("dtsLastDigit-srcLastDigit = {}".format(dstLastDigit - srcLastDigit))
            # print("dtsLastDigit= {}".format(dstLastDigit))
            # print("srcLastDigit= {}".format(srcLastDigit))
            if (dstLastDigit - srcLastDigit) == 1:
                out_port = 2
            elif (dstLastDigit - srcLastDigit) == 2:
                out_port = 2
            elif (dstLastDigit - srcLastDigit) == 3:
                out_port = 3
            elif (dstLastDigit - srcLastDigit) == -1:
                out_port = 3
            elif (dstLastDigit - srcLastDigit) == -2:
                out_port = 2
            elif (dstLastDigit - srcLastDigit) == -3:
                out_port = 2
            else:
                print("dtsLastDigit-srcLastDigit = {}".format(dstLastDigit - srcLastDigit))
                print("dtsLastDigit= {}".format(dstLastDigit))
                print("srcLastDigit= {}".format(srcLastDigit))
        elif in_port == 2:
            if dstLastDigit == swID:
                out_port = 1
            else:
                out_port = 3
        elif in_port == 3:
            # print('here')
            # print('dstLastDigit: {}'.format(dstLastDigit))
            # print('swID :{}'.format(swID))
            if dstLastDigit == swID:
                out_port = 1
            else:
                out_port = 2
        else:
            print('error idk whcih port is flow coming')
            print(in_port)
        return out_port

    def getNextHopPortUDP(self, msg):
        datapath = msg.datapath
        swID = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        ipv4_header = pkt.get_protocol(ipv4.ipv4)
        srcIP = ipv4_header.src
        dstIP = ipv4_header.dst
        srcLastDigit = int(srcIP[-1])
        dstLastDigit = int(dstIP[-1])
        # if we miss everything it will be flood.
        out_port = ofproto.OFPP_FLOOD
        if in_port == 1:
            # print('Packet Coming from port 1')
            # print("dtsLastDigit-srcLastDigit = {}".format(dstLastDigit - srcLastDigit))
            # print("dtsLastDigit= {}".format(dstLastDigit))
            # print("srcLastDigit= {}".format(srcLastDigit))
            if (dstLastDigit - srcLastDigit) == 1:
                out_port = 2
            elif (dstLastDigit - srcLastDigit) == 2:
                out_port = 3
            elif (dstLastDigit - srcLastDigit) == 3:
                out_port = 3
            elif (dstLastDigit - srcLastDigit) == -1:
                out_port = 3
            elif (dstLastDigit - srcLastDigit) == -2:
                out_port = 3
            elif (dstLastDigit - srcLastDigit) == -3:
                out_port = 2
            else:
                print("dtsLastDigit-srcLastDigit = {}".format(dstLastDigit - srcLastDigit))
                print("dtsLastDigit= {}".format(dstLastDigit))
                print("srcLastDigit= {}".format(srcLastDigit))
        elif in_port == 2:
            if dstLastDigit == swID:
                out_port = 1
            else:
                out_port = 3
        elif in_port == 3:
            # print('here')
            # print('dstLastDigit: {}'.format(dstLastDigit))
            # print('swID :{}'.format(swID))
            if dstLastDigit == swID:
                out_port = 1
            else:
                out_port = 2
        else:
            print('invalid port')
            print(in_port)
        return out_port

    def arpReply(self, msg):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        arpPKT = pkt.get_protocol(arp.arp)
        arpReqDstIp = arpPKT.dst_ip
        arpReqSrcIp = arpPKT.src_ip
        # We can use this function since we know
        # which host MAC is associated with which IP
        arpReqDstMAC = self.convertIPtoMAC(arpReqDstIp)
        arpReqSrcMAC = self.convertIPtoMAC(arpReqSrcIp)

        arpReplDestIp = arpReqSrcIp
        arpRepSrcIp = arpReqDstIp
        arpRepSrcMAC = arpReqDstMAC
        arpRepDstMAC = arpReqSrcMAC

        e = ethernet.ethernet(dst=arpRepDstMAC, src=arpRepSrcMAC,
                              ethertype=ether.ETH_TYPE_ARP)
        a = arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4, opcode=2,
                    src_mac=arpRepSrcMAC, src_ip=arpRepSrcIp,
                    dst_mac=arpRepDstMAC, dst_ip=arpReplDestIp)
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(a)
        p.serialize()
        actions = [parser.OFPActionOutput(in_port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=0xffffffff,
                                  in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=p)
        datapath.send_msg(out)
        # print(out)

    def httpRST(self, msg):
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst_MAC = eth.dst
        src_MAC = eth.src
        ipv4_header = pkt.get_protocol(ipv4.ipv4)
        srcIP = ipv4_header.src
        dstIP = ipv4_header.dst
        protoID = ipv4_header.proto
        tcp_header = pkt.get_protocol(tcp.tcp)
        tcp_dst_port = tcp_header.dst_port
        tcp_src_port = tcp_header.src_port
        tcp_seq_no = tcp_header.seq
        rstPkt = packet.Packet()
        ee = ethernet.ethernet(dst=src_MAC, src=dst_MAC, ethertype=ether.ETH_TYPE_IP)
        ipip = ipv4.ipv4(src=dstIP, dst=srcIP, proto=protoID)
        tcptcp = tcp.tcp(src_port=tcp_dst_port, dst_port=tcp_src_port, ack=tcp_seq_no + 1, bits=0b010100)
        rstPkt.add_protocol(ee)
        rstPkt.add_protocol(ipip)
        rstPkt.add_protocol(tcptcp)
        rstPkt.serialize()
        actions = [parser.OFPActionOutput(in_port)]
        data = rstPkt.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)
        datapath.send_msg(out)

    def convertIPtoMAC(self, ipv4_address):
        # We can use this function since we know which host MAC is associated with which IP
        ip_last_dig = int(ipv4_address[-1])
        src_string = '10:00:00:00:00:0{}'.format(ip_last_dig)
        return src_string

