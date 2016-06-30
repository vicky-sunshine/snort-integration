import json

from webob import Response
from ryu.base import app_manager
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.topology.api import get_switch
from ryu.ofproto import ether
from ryu.ofproto import inet
from ryu.ofproto import ofproto_v1_3

from route import urls
from helper import ofp_helper

snort_firewall_instance_name = 'snort_firewall_api_app'
fw_priority = 32768


class SnortFirewall(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(SnortFirewall, self).__init__(*args, **kwargs)
        self.switches = {}
        wsgi = kwargs['wsgi']
        wsgi.register(SnortFirewallController,
                      {snort_firewall_instance_name: self})
        self.topology_api_app = self

    def add_block_rule(self, src_ip, dst_ip, protocol, dst_port, src_port):
        switch_list = get_switch(self.topology_api_app, None)
        for switch in switch_list:
            datapath = switch.dp
            parser = datapath.ofproto_parser

            actions = []  # drop

            # initial match field(IP layer)
            match_dict = self.handle_match(src_ip, dst_ip, protocol,
                                           dst_port, src_port)

            match = parser.OFPMatch(**match_dict)
            ofp_helper.add_flow(datapath, fw_priority, match, actions, 10)

    def handle_match(self, src_ip, dst_ip, protocol, dst_port, src_port):
        # initial match field(IP layer)
        match_dict = {'eth_type': ether.ETH_TYPE_IP}

        if src_ip:
            match_dict.update({'ipv4_src': src_ip})

        if dst_ip:
            match_dict.update({'ipv4_dst': dst_ip})

        if protocol:
            match_dict.update({'ip_proto': protocol})

        # fill into the layer3 and layer 4 protocol
        if src_port:
            if protocol == inet.IPPROTO_TCP:
                match_dict.update({'tcp_src': src_port})
            elif protocol == inet.IPPROTO_UDP:
                match_dict.update({'udp_src': src_port})

        if dst_port:
            if protocol == inet.IPPROTO_TCP:
                match_dict.update({'tcp_dst': dst_port})
            elif protocol == inet.IPPROTO_UDP:
                match_dict.update({'udp_dst': dst_port})

        return match_dict


class SnortFirewallController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(SnortFirewallController, self).__init__(req, link,
                                                      data, **config)
        self.snort_firewall_spp = data[snort_firewall_instance_name]

    @route('firewall', urls.firewall_acl, methods=['PUT'])
    def block_rule_customport(self, req, **kwargs):
        try:
            snort_firewall = self.snort_firewall_spp
            request_tuple = json.loads(req.body)

            src_ip = str(request_tuple.get('src_ip'))
            dst_ip = str(request_tuple.get('dst_ip'))
            src_port = request_tuple.get('src_port')
            dst_port = request_tuple.get('dst_port')
            protocol = str(request_tuple.get('protocol'))

            if protocol == 'TCP':
                protocol = inet.IPPROTO_TCP
            elif protocol == 'UDP':
                protocol = inet.IPPROTO_UDP
            elif protocol == 'ICMP':
                protocol = inet.IPPROTO_ICMP
            else:
                pass

            snort_firewall.add_block_rule(src_ip, dst_ip, protocol,
                                          dst_port, src_port)
        except Exception as e:
            print e
            return Response(status=406)

        return Response(status=202)
