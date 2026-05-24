# -*- coding: utf-8 -*-
from __future__ import print_function
import time
import socket
import datetime
from operator import attrgetter
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4
from ryu.lib import snortlib, hub
from ryu.app.wsgi import ControllerBase, WSGIApplication, route
from webob import Response
import threading
import logging
import json

LOG = logging.getLogger(__name__)

H1_IP = '10.0.0.10'
H2_IP = '10.0.0.20'
H3_IP = '10.0.0.30'
ADMIN_IP = '10.0.0.100'

TRUST_TIMEOUT = 15
ALERT_COOLDOWN = 20
TRUST_REVOKED = 'revoked'
TRUST_BLOCKED = 'blocked'
TRUST_OK = 'ok'

UDP_IP = "127.0.0.1"
UDP_PORT = 8094

sdn_trust_instance = None


def send_to_influx(msg):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.sendto(msg.encode(), (UDP_IP, UDP_PORT))
    except Exception as e:
        LOG.error("[INFLUX] Error sending: %s", e)


class SDNTrustController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {
        'snortlib': snortlib.SnortLib,
        'wsgi': WSGIApplication
    }

    def __init__(self, *args, **kwargs):
        super(SDNTrustController, self).__init__(*args, **kwargs)
        self.snort = kwargs['snortlib']
        self.wsgi = kwargs['wsgi']
        self.mac_to_port = {}
        self.datapaths = {}

        self.trust_state = {H2_IP: TRUST_OK}
        self.attack_count = {H2_IP: 0}
        self.blacklist_h1 = set()
        self.recovery_timer = None
        self.ssh_restricted = False
        self.rate_limit_installed = False
        self._last_internal_alert_time = 0
        self._last_external_alert_time = 0

        socket_config = {'unixsock': True}
        self.snort.set_config(socket_config)
        self.snort.start_socket_server()

        self.wsgi.register(TrustRestAPI, {'controller': self})

        # Iniciar thread de monitorización
        self.monitor_thread = hub.spawn(self._monitor)

        global sdn_trust_instance
        sdn_trust_instance = self

        LOG.info("=== SDN Trust Controller iniciado ===")
        LOG.info("Trust state inicial: %s", self.trust_state)
        LOG.info("Blacklist inicial: %s", self.blacklist_h1)

    # ==================================================
    # Monitoring thread
    # ==================================================
    def _monitor(self):
        while True:
            for dp in self.datapaths.values():
                self._request_stats(dp)
            hub.sleep(10)

    def _request_stats(self, datapath):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                del self.datapaths[datapath.id]

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        FLOW_MSG = "flows,datapath=%x in-port=%x,eth-dst=\"%s\",out-port=%x,packets=%d,bytes=%d %d"
        body = ev.msg.body
        for stat in sorted([flow for flow in body if flow.priority == 1],
                           key=lambda flow: (flow.match['in_port'],
                                             flow.match['eth_dst'])):
            try:
                timestamp = int(datetime.datetime.now().timestamp() * 1000000000)
                msg = FLOW_MSG % (ev.msg.datapath.id,
                                  stat.match['in_port'], stat.match['eth_dst'],
                                  stat.instructions[0].actions[0].port,
                                  stat.packet_count, stat.byte_count,
                                  timestamp)
                send_to_influx(msg)
            except Exception:
                pass

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        PORT_MSG = "ports,datapath=%x,port=%x rx-pkts=%d,rx-bytes=%d,rx-error=%d,tx-pkts=%d,tx-bytes=%d,tx-error=%d %d"
        body = ev.msg.body
        for stat in sorted(body, key=attrgetter('port_no')):
            timestamp = int(datetime.datetime.now().timestamp() * 1000000000)
            msg = PORT_MSG % (ev.msg.datapath.id, stat.port_no,
                              stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                              stat.tx_packets, stat.tx_bytes, stat.tx_errors,
                              timestamp)
            send_to_influx(msg)

    # ==================================================
    # OpenFlow: Switch conectado
    # ==================================================
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        LOG.info("Switch s%s conectado", datapath.id)

    # ==================================================
    # OpenFlow: Packet In
    # ==================================================
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        dst = eth.dst
        src = eth.src
        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        src_ip = ip_pkt.src if ip_pkt else None
        dst_ip = ip_pkt.dst if ip_pkt else None

        # Comprobar blacklist h1
        if src_ip in self.blacklist_h1:
            return

        # Comprobar trust state de h2->h3
        if src_ip == H2_IP and dst_ip == H3_IP:
            state = self.trust_state.get(H2_IP, TRUST_OK)
            if state == TRUST_BLOCKED:
                return
            elif state == TRUST_REVOKED:
                return

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofproto.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)

    # ==================================================
    # Snort: Alerta recibida
    # ==================================================
    @set_ev_cls(snortlib.EventAlert, MAIN_DISPATCHER)
    def _dump_alert(self, ev):
        msg = ev.msg
        alertmsg = msg.alertmsg[0].decode()
        LOG.info("[SNORT ALERT] %s", alertmsg)

        # Deduir src/dst segons tipus d'alerta
        if "h2 to h3" in alertmsg or "Internal" in alertmsg:
            src_ip = H2_IP
            dst_ip = H3_IP
        elif "External" in alertmsg or "SSH" in alertmsg or "Nmap" in alertmsg or "Port Scan" in alertmsg:
            src_ip = H1_IP
            dst_ip = H2_IP
        else:
            src_ip = H1_IP
            dst_ip = H2_IP

        # Enviar alerta a InfluxDB amb src/dst
        timestamp = int(datetime.datetime.now().timestamp() * 1000000000)
        alert_type = alertmsg.replace(' ', '_')
        influx_msg = 'snort_alerts,type="%s",src="%s",dst="%s" value=1 %d' % (
            alert_type, src_ip, dst_ip, timestamp)
        send_to_influx(influx_msg)

        if "External ICMP Flood" in alertmsg or "External TCP Flood" in alertmsg:
            now = time.time()
            if now - self._last_external_alert_time < ALERT_COOLDOWN:
                return
            self._last_external_alert_time = now
            self._block_h1()

        elif "SSH Brute Force" in alertmsg:
            now = time.time()
            if now - self._last_external_alert_time < ALERT_COOLDOWN:
                return
            self._last_external_alert_time = now
            self._block_h1()

        elif "Internal" in alertmsg:
            now = time.time()
            if now - self._last_internal_alert_time < ALERT_COOLDOWN:
                return
            self._last_internal_alert_time = now
            self._handle_internal_attack()

    # ==================================================
    # Bloqueo h1 hacia toda la red
    # ==================================================
    def _block_h1(self):
        if H1_IP in self.blacklist_h1:
            return
        self.blacklist_h1.add(H1_IP)
        LOG.info("[BLOCK] Bloqueando h1 (%s) hacia toda la red", H1_IP)

        timestamp = int(datetime.datetime.now().timestamp() * 1000000000)
        send_to_influx('ryu_events,event=block_h1 value=1 %d' % timestamp)

        for dpid, datapath in self.datapaths.items():
            parser = datapath.ofproto_parser
            match = parser.OFPMatch(eth_type=0x0800, ipv4_src=H1_IP)
            self.add_flow(datapath, 10, match, [])

    # ==================================================
    # Desbloqueo manual h1
    # ==================================================
    def manual_unblock_h1(self):
        if H1_IP in self.blacklist_h1:
            self.blacklist_h1.discard(H1_IP)
            for dpid, datapath in self.datapaths.items():
                ofproto = datapath.ofproto
                parser = datapath.ofproto_parser
                match = parser.OFPMatch(eth_type=0x0800, ipv4_src=H1_IP)
                mod = parser.OFPFlowMod(
                    datapath=datapath,
                    command=ofproto.OFPFC_DELETE,
                    out_port=ofproto.OFPP_ANY,
                    out_group=ofproto.OFPG_ANY,
                    match=match
                )
                datapath.send_msg(mod)
            timestamp = int(datetime.datetime.now().timestamp() * 1000000000)
            send_to_influx('ryu_events,event=unblock_h1 value=1 %d' % timestamp)
            LOG.info("[UNBLOCK] h1 desbloqueado de toda la red")
            return True
        return False

    # ==================================================
    # Gestión ataque interno h2->h3
    # ==================================================
    def _handle_internal_attack(self):
        state = self.trust_state.get(H2_IP, TRUST_OK)

        if state == TRUST_BLOCKED:
            LOG.info("[TRUST] h2 ya está bloqueado permanentemente")
            return

        self.attack_count[H2_IP] += 1

        if self.attack_count[H2_IP] >= 2:
            self.trust_state[H2_IP] = TRUST_BLOCKED
            if self.recovery_timer:
                self.recovery_timer.cancel()
            self._install_block_h2()
            LOG.info("[TRUST] h2 BLOQUEADO PERMANENTEMENTE (ataque #%d)",
                     self.attack_count[H2_IP])
            timestamp = int(datetime.datetime.now().timestamp() * 1000000000)
            send_to_influx('ryu_events,event=h2_blocked_permanent value=1 %d' % timestamp)
        else:
            self.trust_state[H2_IP] = TRUST_REVOKED
            self._install_block_h2()
            LOG.info("[TRUST] h2 confianza REVOCADA temporalmente (ataque #%d)",
                     self.attack_count[H2_IP])
            timestamp = int(datetime.datetime.now().timestamp() * 1000000000)
            send_to_influx('ryu_events,event=h2_trust_revoked value=1 %d' % timestamp)
            if self.recovery_timer:
                self.recovery_timer.cancel()
            self.recovery_timer = threading.Timer(TRUST_TIMEOUT,
                                                   self._auto_recover_h2)
            self.recovery_timer.start()

    # ==================================================
    # Instalar regla de bloqueo h2->h3
    # ==================================================
    def _install_block_h2(self):
        for dpid, datapath in self.datapaths.items():
            parser = datapath.ofproto_parser
            match = parser.OFPMatch(eth_type=0x0800,
                                    ipv4_src=H2_IP,
                                    ipv4_dst=H3_IP)
            self.add_flow(datapath, 10, match, [])
            LOG.info("[FLOW] Regla DROP instalada: h2 -> h3")

    # ==================================================
    # Recovery automático h2 (15s)
    # ==================================================
    def _auto_recover_h2(self):
        if self.trust_state.get(H2_IP) == TRUST_REVOKED:
            self.trust_state[H2_IP] = TRUST_OK
            self._remove_block_h2()
            LOG.info("[RECOVERY] h2 confianza RESTAURADA automáticamente")
            timestamp = int(datetime.datetime.now().timestamp() * 1000000000)
            send_to_influx('ryu_events,event=h2_auto_recovery value=1 %d' % timestamp)

    # ==================================================
    # Recovery manual h2
    # ==================================================
    def manual_recover_h2(self):
        if self.trust_state.get(H2_IP) == TRUST_BLOCKED:
            self.trust_state[H2_IP] = TRUST_OK
            self.attack_count[H2_IP] = 0
            self._remove_block_h2()
            LOG.info("[RECOVERY] h2 confianza RESTAURADA manualmente")
            timestamp = int(datetime.datetime.now().timestamp() * 1000000000)
            send_to_influx('ryu_events,event=h2_manual_recovery value=1 %d' % timestamp)
            return True
        return False

    # ==================================================
    # Eliminar regla de bloqueo h2->h3
    # ==================================================
    def _remove_block_h2(self):
        for dpid, datapath in self.datapaths.items():
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser
            match = parser.OFPMatch(eth_type=0x0800,
                                    ipv4_src=H2_IP,
                                    ipv4_dst=H3_IP)
            mod = parser.OFPFlowMod(
                datapath=datapath,
                command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                match=match
            )
            datapath.send_msg(mod)
            self.mac_to_port = {}
            LOG.info("[FLOW] Regla DROP eliminada: h2 -> h3")

    # ==================================================
    # Instalar rate limit h2->h3
    # ==================================================
    def install_rate_limit_h2_h3(self):
        if self.rate_limit_installed:
            return False
        self.rate_limit_installed = True

        for dpid, datapath in self.datapaths.items():
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            bands = [parser.OFPMeterBandDrop(rate=1000, burst_size=100)]
            mod = parser.OFPMeterMod(
                datapath=datapath,
                command=ofproto.OFPMC_ADD,
                flags=ofproto.OFPMF_KBPS,
                meter_id=1,
                bands=bands
            )
            datapath.send_msg(mod)

            match = parser.OFPMatch(eth_type=0x0800,
                                    ipv4_src=H2_IP,
                                    ipv4_dst=H3_IP)
            inst = [
                parser.OFPInstructionMeter(1),
                parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                    [parser.OFPActionOutput(ofproto.OFPP_NORMAL)])
            ]
            mod = parser.OFPFlowMod(datapath=datapath,
                                     priority=5,
                                     match=match,
                                     instructions=inst)
            datapath.send_msg(mod)

        timestamp = int(datetime.datetime.now().timestamp() * 1000000000)
        send_to_influx('ryu_events,event=rate_limit_installed value=1 %d' % timestamp)
        LOG.info("[RATE LIMIT] Instalado: h2->h3 max 1Mbps")
        return True

    # ==================================================
    # Eliminar rate limit h2->h3
    # ==================================================
    def remove_rate_limit_h2_h3(self):
        if not self.rate_limit_installed:
            return False
        self.rate_limit_installed = False

        for dpid, datapath in self.datapaths.items():
            ofproto = datapath.ofproto
            parser = datapath.ofproto_parser

            mod = parser.OFPMeterMod(
                datapath=datapath,
                command=ofproto.OFPMC_DELETE,
                flags=ofproto.OFPMF_KBPS,
                meter_id=1
            )
            datapath.send_msg(mod)

            match = parser.OFPMatch(eth_type=0x0800,
                                    ipv4_src=H2_IP,
                                    ipv4_dst=H3_IP)
            mod = parser.OFPFlowMod(
                datapath=datapath,
                command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
                match=match
            )
            datapath.send_msg(mod)

        timestamp = int(datetime.datetime.now().timestamp() * 1000000000)
        send_to_influx('ryu_events,event=rate_limit_removed value=1 %d' % timestamp)
        LOG.info("[RATE LIMIT] Eliminado: h2->h3")
        return True

    # ==================================================
    # Restringir SSH solo a admin
    # ==================================================
    def restrict_ssh_to_admin(self):
        if self.ssh_restricted:
            return False
        self.ssh_restricted = True

        for dpid, datapath in self.datapaths.items():
            parser = datapath.ofproto_parser

            match_allow = parser.OFPMatch(eth_type=0x0800,
                                          ipv4_src=ADMIN_IP,
                                          ipv4_dst=H2_IP,
                                          ip_proto=6,
                                          tcp_dst=22)
            self.add_flow(datapath, 20, match_allow,
                         [parser.OFPActionOutput(datapath.ofproto.OFPP_NORMAL)])

            match_block = parser.OFPMatch(eth_type=0x0800,
                                          ipv4_dst=H2_IP,
                                          ip_proto=6,
                                          tcp_dst=22)
            self.add_flow(datapath, 15, match_block, [])

        timestamp = int(datetime.datetime.now().timestamp() * 1000000000)
        send_to_influx('ryu_events,event=ssh_restricted value=1 %d' % timestamp)
        LOG.info("[SSH] Restringiendo SSH h2 solo a %s", ADMIN_IP)
        return True

    # ==================================================
    # Helper: añadir flow
    # ==================================================
    def add_flow(self, datapath, priority, match, actions):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                 match=match, instructions=inst)
        datapath.send_msg(mod)


# ==================================================
# API REST
# ==================================================
class TrustRestAPI(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(TrustRestAPI, self).__init__(req, link, data, **config)
        self.controller = data['controller']

    @route('trust', '/trust/status', methods=['GET'])
    def trust_status(self, req, **kwargs):
        body = json.dumps({
            'trust_state': self.controller.trust_state,
            'attack_count': self.controller.attack_count,
            'blacklist_h1': list(self.controller.blacklist_h1),
            'ssh_restricted': self.controller.ssh_restricted,
            'rate_limit_installed': self.controller.rate_limit_installed
        }).encode('utf-8')
        return Response(content_type='application/json', body=body)

    @route('trust', '/trust/restore/h2', methods=['POST'])
    def restore_trust_h2(self, req, **kwargs):
        success = self.controller.manual_recover_h2()
        if success:
            body = json.dumps({'status': 'ok',
                               'msg': 'Trust restored for h2'}).encode('utf-8')
            return Response(content_type='application/json', body=body)
        else:
            body = json.dumps({'status': 'error',
                               'msg': 'h2 not permanently blocked'}).encode('utf-8')
            return Response(content_type='application/json', body=body, status=400)

    @route('trust', '/blacklist/remove/h1', methods=['POST'])
    def unblock_h1(self, req, **kwargs):
        success = self.controller.manual_unblock_h1()
        if success:
            body = json.dumps({'status': 'ok',
                               'msg': 'h1 desbloqueado'}).encode('utf-8')
            return Response(content_type='application/json', body=body)
        else:
            body = json.dumps({'status': 'error',
                               'msg': 'h1 no estaba bloqueado'}).encode('utf-8')
            return Response(content_type='application/json', body=body, status=400)

    @route('trust', '/ratelimit/h2-h3', methods=['POST'])
    def install_ratelimit(self, req, **kwargs):
        success = self.controller.install_rate_limit_h2_h3()
        if success:
            body = json.dumps({'status': 'ok',
                               'msg': 'Rate limit instalado h2->h3: 1Mbps'}).encode('utf-8')
            return Response(content_type='application/json', body=body)
        else:
            body = json.dumps({'status': 'error',
                               'msg': 'Rate limit ya estaba instalado'}).encode('utf-8')
            return Response(content_type='application/json', body=body, status=400)

    @route('trust', '/ratelimit/remove/h2-h3', methods=['POST'])
    def remove_ratelimit(self, req, **kwargs):
        success = self.controller.remove_rate_limit_h2_h3()
        if success:
            body = json.dumps({'status': 'ok',
                               'msg': 'Rate limit eliminado h2->h3'}).encode('utf-8')
            return Response(content_type='application/json', body=body)
        else:
            body = json.dumps({'status': 'error',
                               'msg': 'No había rate limit instalado'}).encode('utf-8')
            return Response(content_type='application/json', body=body, status=400)

    @route('trust', '/firewall/ssh/restrict', methods=['POST'])
    def restrict_ssh(self, req, **kwargs):
        success = self.controller.restrict_ssh_to_admin()
        if success:
            body = json.dumps({'status': 'ok',
                               'msg': 'SSH restringido solo a admin (10.0.0.100)'}).encode('utf-8')
            return Response(content_type='application/json', body=body)
        else:
            body = json.dumps({'status': 'error',
                               'msg': 'SSH ya estaba restringido'}).encode('utf-8')
            return Response(content_type='application/json', body=body, status=400)
