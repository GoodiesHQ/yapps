"""
YAPPS Scanner Implementation
"""

from . import WorkPool, ArgTypes
from enum import IntEnum, auto
from typing import NamedTuple, Union
import aiodns
import asyncio
import ipaddress
import janus
import sys


class ScanState(IntEnum):
    """
    Possible values for the state of a particular host/port combo
    """
    OPEN = auto()       # Port is open and a reply was received
    CLOSED = auto()     # Connection was actively refused
    TIMEOUT = auto()    # Port did not respond within the desired time frame
    UNKNOWN = auto()    # Unknown error occurred (unlikely)


class ScanInfo(NamedTuple):
    """
    Information gathered from each port scan
    """
    host: str
    port: int
    state: ScanState
    banner: str


class Scanner:
    """
    A simple asynchronous port scanner
    """

    def __init__(self,
                 workers: int = 10,
                 timeout: float = 3.0,
                 banner: bool = False,
                 bufsize: int = 1024,
                 result_queue: janus.Queue = None,
                 resolver: aiodns.DNSResolver = None):
        self._timeout = timeout
        self._banner = banner
        self._bufsize = bufsize
        self._pool = WorkPool(workers, complete_callback=self._on_scan_complete)
        self._resolver = resolver or aiodns.DNSResolver()
        self._results = result_queue or janus.Queue()

    def _on_scan_complete(self):
        """
        Once all scheduled scans are complete, put a None object onto the
        result queue to indicate it is done
        """
        self._results.sync_q.put(None)

    async def host(self, host, query_type="A"):
        try:
            return ipaddress.ip_address(host)
        except ValueError:
            result = await self._resolver.query(host, query_type)
            if result:
                return ipaddress.ip_address(result[0].host)

    async def check_port(self, host: str, port: int, query_type: str = "A") -> ScanInfo:
        """
        Connect to a particular host address and port combination to determine the
        port state.
        :param host: IP address of the desired host
        :param port: port number to check
        :param query_type: DNS query type to use (ONLY used if the host is a domain name)
        :return: ScanInfo object
        """
        addr = await self.host(host, query_type)
        fut = asyncio.open_connection(str(addr), port)
        state, banner = ScanState.UNKNOWN, None
        try:
            r, w = await asyncio.wait_for(fut, timeout=self._timeout)
            # Port is open, attempt to gather fingerprint data
            state = ScanState.OPEN
            if self._banner:
                w.write(b"\r\n\r\n")
                banner = await asyncio.wait_for(r.read(self._bufsize), timeout=self._timeout)
                trans = str.maketrans("", "", "\r\n")
                banner = banner.decode("utf-8", "ignore").translate(trans)
            w.close()
        except asyncio.TimeoutError:
            # A timeout occurred. If a timeout occurred reading the banner, do
            if state == ScanState.UNKNOWN:
                state = ScanState.TIMEOUT
        except (ConnectionRefusedError, OSError):
            # Connection was actively refused
            state = ScanState.CLOSED
        except Exception as e:
            print(f"Error Type: {type(e)}", e, file=sys.stderr, sep="\n")
        finally:
            scan_info = ScanInfo(host, port, state, banner)
            await self._results.async_q.put(scan_info)
            return scan_info

    async def check_host(self, host: str, ports: Union[str, list, tuple, set], *callbacks):
        ports = ArgTypes.multi_num_range(ports) if isinstance(ports, str) else list(ports)
        asyncio.ensure_future(self._pool.run_many(
            (self.check_port(host, port) for port in ports),
            *callbacks
        ))

    async def check_net(self, network: str, ports: Union[str, list, tuple, set], *callbacks):
        ports = ArgTypes.multi_num_range(ports) if isinstance(ports, str) else list(ports)
        asyncio.ensure_future(self._pool.run_many(
            (self.check_host(str(host), ports)
             for host in ipaddress.ip_network(network, strict=False)),
            *callbacks
        ))

    async def wait_for_complete(self):
        await self._pool.join()

    def __aiter__(self):
        return self

    async def __anext__(self):
        value = await self._results.async_q.get()
        if value:
            return value
        raise StopAsyncIteration

    async def __aenter__(self):
        return self

    def __aexit__(self, exc_type, exc_val, exc_tb):
        return self.wait_for_complete()
