def add_flow(datapath, priority, match, actions,
             hard_timeout=0, buffer_id=None):
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser

    inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                         actions)]
    if buffer_id:
        mod = parser.OFPFlowMod(datapath=datapath,
                                hard_timeout=hard_timeout,
                                buffer_id=buffer_id,
                                priority=priority,
                                match=match,
                                instructions=inst)
    else:
        mod = parser.OFPFlowMod(datapath=datapath,
                                hard_timeout=hard_timeout,
                                priority=priority,
                                match=match,
                                instructions=inst)
    datapath.send_msg(mod)


def del_flow(datapath, match):
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser
    mod = parser.OFPFlowMod(datapath=datapath,
                            command=ofproto.OFPFC_DELETE_STRICT,
                            out_port=ofproto.OFPP_ANY,
                            out_group=ofproto.OFPG_ANY,
                            match=match)
    datapath.send_msg(mod)


def send_packet(datapath, pkt, port):
    ofproto = datapath.ofproto
    parser = datapath.ofproto_parser
    pkt.serialize()

    data = pkt.data
    actions = [parser.OFPActionOutput(port=port)]
    out = parser.OFPPacketOut(datapath=datapath,
                              buffer_id=ofproto.OFP_NO_BUFFER,
                              in_port=ofproto.OFPP_CONTROLLER,
                              actions=actions,
                              data=data)
    datapath.send_msg(out)
