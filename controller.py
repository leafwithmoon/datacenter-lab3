
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

        if eth.ethertype == ether_types.ETH_TYPE_ARP:
            arpPKT = pkt.get_protocol(arp.arp)
            if arpPKT.opcode == 1:
                self.arpHandler(msg)

        elif eth.ethertype == ether_types.ETH_TYPE_IP:
            header = pkt.get_protocol(ipv4.ipv4)
            if header.proto == 1:
                out_port = self.tcpHandler(msg)
                actions = [datapath.ofproto_parser.OFPActionOutput(out_port)]
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst_MAC,
                                        eth_type=ether_types.ETH_TYPE_IP,
                                        ipv4_dst=header.dst, ip_proto=header.proto)

                if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                    self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                    return

                else:
                    self.add_flow(datapath, 1, match, actions)

                out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath,
                                                           buffer_id=msg.buffer_id,
                                                           in_port=in_port, actions=actions,
                                                           data=pkt)
                datapath.send_msg(out)

            if header.proto == 6:
                tcp_header = pkt.get_protocol(tcp.tcp)
                if tcp_header.dst_port == 80 and (header.src == '10.0.0.2' or header.src == '10.0.0.4'):
                    rst_pkt = packet.Packet()
                    rst_pkt.add_protocol(ethernet.ethernet(ethertype=eth.ethertype, src=dst_MAC, dst=src_MAC))
                    rst_pkt.add_protocol(ipv4.ipv4(src=header.dst, dst=header.src, proto=6))
                    rst_pkt.add_protocol(tcp.tcp(src_port=tcp_header.dst_port,
                                                 dst_port=tcp_header.src_port,
                                                 ack=tcp_header.seq + 1, bits=0b010100))
                    self._send_packet(datapath, in_port, rst_pkt)

                else:
                    actions = [datapath.ofproto_parser.OFPActionOutput(self.tcpHandler(msg))]
                    match = parser.OFPMatch(in_port=in_port, eth_dst=dst_MAC, eth_type=ether_types.ETH_TYPE_IP,
                                            ipv4_dst=header.dst, ip_proto=header.proto)
                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                        self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                        return
                    else:
                        self.add_flow(datapath, 1, match, actions)
                    out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath,
                                                               buffer_id=msg.buffer_id,
                                                               in_port=in_port,
                                                               actions=actions, data=pkt)
                    datapath.send_msg(out)

            if header.proto == 17:
                if header.src == '10.0.0.1' or header.src == '10.0.0.4':
                    return
                else:
                    actions = [datapath.ofproto_parser.OFPActionOutput(self.udpHandler(msg))]
                    match = parser.OFPMatch(in_port=in_port, eth_dst=dst_MAC, eth_type=ether_types.ETH_TYPE_IP,
                                            ipv4_dst=header.dst, ip_proto=header.proto)
                    if msg.buffer_id != ofproto.OFP_NO_BUFFER:
                        self.add_flow(datapath, 1, match, actions, msg.buffer_id)
                        return
                    else:
                        self.add_flow(datapath, 1, match, actions)
                    out = datapath.ofproto_parser.OFPPacketOut(datapath=datapath,
                                                               buffer_id=msg.buffer_id,
                                                               in_port=in_port,
                                                               actions=actions, data=pkt)
                    datapath.send_msg(out)

    def _send_packet(self, datapath, port, pkt):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        pkt.serialize()
        self.logger.info("packet-out %s" % (pkt,))
        data = pkt.data
        actions = [parser.OFPActionOutput(port=port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=ofproto.OFP_NO_BUFFER,
                                  in_port=ofproto.OFPP_CONTROLLER, actions=actions, data=data)
        datapath.send_msg(out)

    def arpHandler(self, msg):
        reqDstMAC = '10:00:00:00:00:0' + str(packet.Packet(msg.data).get_protocol(arp.arp).dst_ip[-1])
        reqSrcMAC = '10:00:00:00:00:0' + str(packet.Packet(msg.data).get_protocol(arp.arp).src_ip[-1])
        pkt = packet.Packet()
        pkt.add_protocol(ethernet.ethernet(dst=reqSrcMAC, src=reqDstMAC,
                              ethertype=ether.ETH_TYPE_ARP))
        pkt.add_protocol(arp.arp(hwtype=1, proto=0x0800, hlen=6, plen=4, opcode=2,
                    src_mac=reqDstMAC, src_ip=packet.Packet(msg.data).get_protocol(arp.arp).dst_ip,
                    dst_mac=reqSrcMAC, dst_ip=packet.Packet(msg.data).get_protocol(arp.arp).src_ip))
        pkt.serialize()
        actions = [msg.datapath.ofproto_parser.OFPActionOutput(msg.match['in_port'])]
        out = msg.datapath.ofproto_parser.OFPPacketOut(datapath=msg.datapath, buffer_id=0xffffffff,
                                  in_port=msg.datapath.ofproto.OFPP_CONTROLLER, actions=actions, data=p)
        msg.datapath.send_msg(out)


    def tcpHandler(self, msg):
        in_port = msg.match['in_port']
        header = packet.Packet(msg.data).get_protocol(ipv4.ipv4)
        srcHost = int(header.src[-1])
        dstHost = int(header.dst[-1])
        out_port = msg.datapath.ofproto.OFPP_FLOOD
        if in_port == 1:
            if (dstHost - srcHost) == 3 or (dstHost - srcHost) == -1:
                out_port = 3
            else:
                out_port = 2
        elif in_port == 2:
            if dstHost == msg.datapath.id:
                out_port = 1
            else:
                out_port = 3
        elif in_port == 3:
            if dstHost == msg.datapath.id:
                out_port = 1
            else:
                out_port = 2
        else:
            print('invalid port')
        return out_port

    def udpHandler(self, msg):
        in_port = msg.match['in_port']
        header = packet.Packet(msg.data).get_protocol(ipv4.ipv4)
        srcHost = int(header.src[-1])
        dstHost = int(header.dst[-1])
        out_port = msg.datapath.ofproto.OFPP_FLOOD
        if in_port == 1:
            if (dstHost - srcHost) == 1 or (dstHost - srcHost) == -3:
                out_port = 2
            else:
                out_port = 3

        elif in_port == 2:
            if dstHost == msg.datapath.id:
                out_port = 1
            else:
                out_port = 3
        elif in_port == 3:
            if dstHost == msg.datapath.id:
                out_port = 1
            else:
                out_port = 2
        else:
            print('invalid port')
        return out_port




