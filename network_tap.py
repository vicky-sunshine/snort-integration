from webob import Response
from ryu.base import app_manager
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from ryu.controller import ofp_event
from ryu.controller.handler import set_ev_cls
from ryu.controller.handler import CONFIG_DISPATCHER

from helper import ofp_helper
from route import urls

network_tap_instance_name = 'network_tap_api_app'

# Port 2, connect to Lan
# Port 3, connect to Internet
# Port 4, mirror both 2 and 3
tap_inport = 2
tap_outport = 3
mirror_port = 4

tap_priority = 100


class NetworkTap(app_manager.RyuApp):
    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(NetworkTap, self).__init__(*args, **kwargs)
        self.switches = {}
        wsgi = kwargs['wsgi']
        wsgi.register(NetworkTapController,
                      {network_tap_instance_name: self})
        self.topology_api_app = self

    def _reset_flow(self, datapath):
        parser = datapath.ofproto_parser

        # inport -> outport
        # inport -> mirror port
        in_match = parser.OFPMatch(in_port=tap_inport)
        in_actions = [parser.OFPActionOutput(tap_outport),
                      parser.OFPActionOutput(mirror_port)]
        ofp_helper.add_flow(datapath, tap_priority, in_match, in_actions)

        # outport -> mirror port
        # outport -> inport
        out_match = parser.OFPMatch(in_port=tap_outport)
        out_actions = [parser.OFPActionOutput(tap_inport),
                       parser.OFPActionOutput(mirror_port)]
        ofp_helper.add_flow(datapath, tap_priority, out_match, out_actions)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self._reset_flow(datapath)


class NetworkTapController(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(NetworkTapController, self).__init__(req, link, data, **config)
        self.stat_monitor_spp = data[network_tap_instance_name]

    @route('network_tap', urls.tap_inport, methods=['PUT'])
    def hello(self, req, **kwargs):
        # just a dump API
        return Response(status=200)
