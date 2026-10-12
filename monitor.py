
from collections import defaultdict, deque
from datetime import datetime, timezone
from threading import Thread, Event, Lock
import time
import os

from database import add_event


class IDSMonitor:
    """
    Educational rule-based Intrusion Detection System.

    Local machine:
        Captures packet metadata using Scapy.

    Render:
        Live packet capture is disabled.
        Use the dashboard's Demo Mode for simulated events.
    """

    def __init__(self):
        self._thread = None
        self._stop_event = Event()
        self._lock = Lock()
        self._running = False
        self._error = None
        self._interface = None

        self._packet_times = defaultdict(deque)
        self._ports = defaultdict(deque)
        self._alert_cooldown = {}

    def status(self):
        with self._lock:
            return {
                "running": self._running,
                "interface": self._interface,
                "error": self._error
            }

    def start(self, interface=None):
        # Render does not provide the required permissions
        # for raw packet capture in this deployment.
        if os.environ.get("RENDER"):
            message = (
                "Live packet capture is unavailable on Render. "
                "Use Demo Mode for simulated events, or run locally "
                "on an authorized network."
            )
            with self._lock:
                self._error = message
                self._running = False
                self._interface = None

            return {
                "ok": False,
                "message": message
            }

        with self._lock:
            if self._running:
                return {
                    "ok": True,
                    "message": "Monitoring is already running."
                }

            self._stop_event.clear()
            self._error = None
            self._interface = interface

            self._thread = Thread(
                target=self._capture_loop,
                args=(interface,),
                daemon=True
            )

            self._running = True
            self._thread.start()

        return {
            "ok": True,
            "message": (
                "Monitor started. Capture only on a network "
                "you are authorized to monitor."
            )
        }

    def stop(self):
        self._stop_event.set()

        with self._lock:
            if not self._running:
                return {
                    "ok": True,
                    "message": "Monitoring is already stopped."
                }

        return {
            "ok": True,
            "message": "Stop requested."
        }

    def _capture_loop(self, interface):
        try:
            from scapy.all import sniff

            while not self._stop_event.is_set():
                sniff(
                    iface=interface,
                    prn=self._handle_packet,
                    store=False,
                    timeout=1,
                    stop_filter=lambda packet: (
                        self._stop_event.is_set()
                    )
                )

        except Exception as exc:
            with self._lock:
                self._error = f"{type(exc).__name__}: {exc}"

        finally:
            with self._lock:
                self._running = False

    def _handle_packet(self, packet):
        from scapy.all import IP, TCP, UDP, ICMP

        if IP not in packet:
            return

        ip = packet[IP]
        src_ip = ip.src
        dst_ip = ip.dst

        now = time.time()

        timestamp = datetime.now(
            timezone.utc
        ).astimezone().isoformat(timespec="seconds")

        protocol = "OTHER"
        dst_port = None

        if TCP in packet:
            protocol = "TCP"
            dst_port = int(packet[TCP].dport)

        elif UDP in packet:
            protocol = "UDP"
            dst_port = int(packet[UDP].dport)

        elif ICMP in packet:
            protocol = "ICMP"

        # Track recent packets from each source IP.
        packet_times = self._packet_times[src_ip]
        packet_times.append(now)

        while (
            packet_times
            and now - packet_times[0] > 10
        ):
            packet_times.popleft()

        # Track destination ports over the last 30 seconds.
        if dst_port is not None:
            port_entries = self._ports[src_ip]
            port_entries.append((now, dst_port))

            while (
                port_entries
                and now - port_entries[0][0] > 30
            ):
                port_entries.popleft()

        self._record(
            "LIVE",
            src_ip,
            dst_ip,
            protocol,
            dst_port,
            "INFO",
            "Packet observed",
            timestamp
        )

        # Rule 1: High packet rate.
        if len(packet_times) >= 25:
            self._alert_once(
                f"rate:{src_ip}",
                now,
                20,
                "LIVE",
                src_ip,
                dst_ip,
                protocol,
                dst_port,
                "MEDIUM",
                "High packet rate: at least 25 packets "
                "from this source within 10 seconds",
                timestamp
            )

        # Rule 2: Possible port scan.
        if dst_port is not None:
            distinct_ports = {
                port for _, port in self._ports[src_ip]
            }

            if len(distinct_ports) >= 8:
                self._alert_once(
                    f"scan:{src_ip}",
                    now,
                    30,
                    "LIVE",
                    src_ip,
                    dst_ip,
                    protocol,
                    dst_port,
                    "HIGH",
                    "Possible port scan: at least 8 "
                    "distinct destination ports within 30 seconds",
                    timestamp
                )

    def _alert_once(
        self,
        key,
        now,
        cooldown,
        source,
        src_ip,
        dst_ip,
        protocol,
        port,
        severity,
        message,
        timestamp
    ):
        last = self._alert_cooldown.get(key, 0)

        if now - last >= cooldown:
            self._alert_cooldown[key] = now

            self._record(
                source,
                src_ip,
                dst_ip,
                protocol,
                port,
                severity,
                message,
                timestamp
            )

    def _record(
        self,
        source,
        src_ip,
        dst_ip,
        protocol,
        port,
        severity,
        message,
        timestamp
    ):
        try:
            add_event(
                source,
                src_ip,
                dst_ip,
                protocol,
                port,
                severity,
                message,
                timestamp
            )

        except Exception as exc:
            with self._lock:
                self._error = f"Database error: {exc}"
