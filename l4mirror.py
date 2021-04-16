from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_4
from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import in_proto
from ryu.lib.packet import ipv4
from ryu.lib.packet import tcp
from ryu.lib.packet.ether_types import ETH_TYPE_IP

class L4Mirror14(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_4.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(L4Mirror14, self).__init__(*args, **kwargs)
        self.ht = {}

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def features_handler(self, ev):
        dp = ev.msg.datapath
        ofp, psr = (dp.ofproto, dp.ofproto_parser)
        acts = [psr.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self.add_flow(dp, 0, psr.OFPMatch(), acts)

    def add_flow(self, dp, prio, match, acts, buffer_id=None):
        ofp, psr = (dp.ofproto, dp.ofproto_parser)
        bid = buffer_id if buffer_id is not None else ofp.OFP_NO_BUFFER
        ins = [psr.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, acts)]
        mod = psr.OFPFlowMod(datapath=dp, buffer_id=bid, priority=prio,
                                match=match, instructions=ins)
        dp.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        in_port, pkt = (msg.match['in_port'], packet.Packet(msg.data))
        dp = msg.datapath
        ofp, psr, did = (dp.ofproto, dp.ofproto_parser, format(dp.id, '016d'))
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        iph = pkt.get_protocols(ipv4.ipv4)
        tcph = pkt.get_protocols(tcp.tcp)

        out_port = 2 if in_port == 1 else 1
        #
        # write your code here
        if eth.ethertype == ETH_TYPE_IP and len(tcph) > 0:
            if tcph[0].bits == 2 and in_port == 2:
                self.ht.setdefault((iph[0].src, iph[0].dst, tcph[0].src_port, tcph[0].dst_port), 0)
                acts = [psr.OFPActionOutput(out_port), psr.OFPActionOutput(3)]
                self.ht.setdefault((iph[0].src, iph[0].dst, tcph[0].src_port, tcph[0].dst_port), 0)
                count = self.ht.get((iph[0].src, iph[0].dst, tcph[0].src_port, tcph[0].dst_port))
                self.ht[(iph[0].src, iph[0].dst, tcph[0].src_port, tcph[0].dst_port)] = count + 1
            else:
                dst, src = (eth.dst, eth.src)
                self.logger.info(f'Packet_in_handler: The packet_id {did} is sent from IP: {iph[0].src} MAC: {src} to IP: {iph[0].dst} MAC: {dst}.')
                if not (iph[0].src, iph[0].dst, tcph[0].src_port, tcph[0].dst_port) in self.ht:
                    acts = [psr.OFPActionOutput(out_port)]
                    match = psr.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst, ipv4_src=iph[0].src,
                                         ipv4_dst=iph[0].dst,
                                         tcp_src=tcph[0].src_port, tcp_dst=tcph[0].dst_port)
                    self.add_flow(dp, 1, match, acts)
                    return
                else:
                    if in_port == 1:
                        acts = [psr.OFPActionOutput(out_port)]
                        match = psr.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst, ipv4_src=iph[0].src, ipv4_dst=iph[0].dst,
                                             tcp_src=tcph[0].src_port, tcp_dst=tcph[0].dst_port)
                        self.add_flow(dp, 1, match, acts)
                        self.ht.setdefault((iph[0].src, iph[0].dst, tcph[0].src_port, tcph[0].dst_port), 0)
                        count = self.ht.get((iph[0].src, iph[0].dst, tcph[0].src_port, tcph[0].dst_port))
                        self.ht[(iph[0].src, iph[0].dst, tcph[0].src_port, tcph[0].dst_port)] = count + 1
                        return
                    else:
                        if in_port == 2:
                            if (iph[0].dst, iph[0].src, tcph[0].dst_port, tcph[0].src_port) in self.ht:
                                acts = [psr.OFPActionOutput(ofp.OFPPC_NO_FWD)]
                                self.ht.setdefault((iph[0].src, iph[0].dst, tcph[0].src_port, tcph[0].dst_port), 0)
                                count = self.ht.get((iph[0].src, iph[0].dst, tcph[0].src_port, tcph[0].dst_port))
                                self.ht[(iph[0].src, iph[0].dst, tcph[0].src_port, tcph[0].dst_port)] = count + 1
                            else:
                                acts = [psr.OFPActionOutput(out_port), psr.OFPActionOutput(3)]
                                self.ht.setdefault((iph[0].src, iph[0].dst, tcph[0].src_port, tcph[0].dst_port), 0)
                                count = self.ht.get((iph[0].src, iph[0].dst, tcph[0].src_port, tcph[0].dst_port))
                                self.ht[(iph[0].src, iph[0].dst, tcph[0].src_port, tcph[0].dst_port)] = count + 1
                if self.ht.get((iph[0].src, iph[0].dst, tcph[0].src_port, tcph[0].dst_port)) == 10:
                    self.ht.clear()
                    acts = [psr.OFPActionOutput(ofp.OFPPC_NO_FWD)]
        else:
            self.logger.info('This is not a TCP packet.')
            print('This is not a TCP packet.')
            acts = [psr.OFPActionOutput(out_port)]
        #
        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        out = psr.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                               in_port=in_port, actions=acts, data=data)
        dp.send_msg(out)
