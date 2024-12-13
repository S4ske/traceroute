from typer import Typer, Argument, Option, echo, run
from typing import Iterable
from dataclasses import dataclass
from scapy.all import sr1
from scapy.layers.inet import IP, ICMP, TCP, UDP
from scapy.layers.inet6 import IPv6
from datetime import datetime
import ipaddress
from ipwhois import IPWhois, IPDefinedError
from concurrent.futures import ThreadPoolExecutor, as_completed


class ProtocolException(Exception):
    pass


@dataclass
class NodeInfo:
    ip: str | None
    time_mcs: int
    autonomous_system: str | None = None


app = Typer()


@app.command()
def traceroute(
    timeout: int = Option(2, "-t"),
    port: int = Option(80, "-p"),
    max_requests_count: int = Option(5, "-n"),
    verbose: bool = Option(False, "-v", is_flag=True),
    max_hops_count: int = Option(30, "--hops", help="Максимальное количество хопов"),
    ip_address: str = Argument(),
    protocol: str = Argument(),
) -> None:
    try:
        i = 1
        for result in solve(
            timeout,
            port,
            max_requests_count,
            verbose,
            max_hops_count,
            ip_address,
            protocol,
        ):
            echo(
                " ".join(
                    (
                        str(i),
                        result.ip if result.ip else "*",
                        (
                            str(result.time_mcs // 1000)
                            if result.time_mcs >= 1000
                            else "<1"
                        )
                        + "ms",
                        (
                            str(result.autonomous_system)
                            if result.autonomous_system
                            else "NA"
                        )
                        if verbose
                        else "",
                    )
                )
            )
            if result.ip == ip_address:
                return
            i += 1
    except ProtocolException:
        echo("Этот протокол не поддерживается")


def solve(
    timeout: int,
    port: int,
    max_requests_count: int,
    verbose: bool,
    max_hops_count: int,
    ip_address: str,
    protocol: str,
) -> Iterable[NodeInfo]:
    for ttl in range(1, max_hops_count + 1):
        with ThreadPoolExecutor(max_requests_count) as executor:
            futures = [
                executor.submit(
                    handle_packet, timeout, port, verbose, ttl, ip_address, protocol
                )
                for _ in range(max_requests_count)
            ]
            for future in as_completed(futures):
                node_info: NodeInfo = future.result()
                yield node_info
                if node_info.ip == ip_address:
                    return
                break


def handle_packet(
    timeout: int, port: int, verbose: bool, ttl: int, ip_address: str, protocol: str
) -> NodeInfo:
    packet = build_packet(port, ttl, ip_address, protocol)
    start_time = datetime.now()
    reply = sr1(packet, verbose=0, timeout=timeout)
    response_time = (datetime.now() - start_time).microseconds
    if reply is None:
        return NodeInfo(ip=None, time_mcs=response_time)
    else:
        return NodeInfo(
            ip=reply.src,
            time_mcs=response_time,
            autonomous_system=get_asn(reply.src) if verbose else None,
        )


def build_packet(port: int, ttl: int, ip_address: str, protocol: str) -> IP | IPv6:
    lower_protocol = protocol.lower()
    if is_ipv6(ip_address):
        packet = IPv6(dst=ip_address, hlim=ttl)
    else:
        packet = IP(dst=ip_address, ttl=ttl)
    if lower_protocol == "tcp":
        packet /= TCP(dport=port, flags="S")
    elif lower_protocol == "udp":
        packet /= UDP(dport=port)
    elif lower_protocol == "icmp":
        packet /= ICMP()
    else:
        raise ProtocolException()
    return packet


def is_ipv6(ip_address: str) -> bool:
    return ipaddress.ip_address(ip_address).version == 6


def get_asn(ip_address: str) -> str | None:
    try:
        obj = IPWhois(ip_address, 2)
        result = obj.lookup_rdap()
        return result.get("asn")
    except IPDefinedError:
        return None


if __name__ == "__main__":
    run(traceroute)
