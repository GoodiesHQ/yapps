#!/usr/bin/env python3

"""
Stupid simple asyncio-based port scanner.
Not very performant (it's python after all...), but it's faster than (at least) 99% of other pure-python scanners out there.
Very simple usage. Doesn't perform anything other than TCP port status checking.
"""

from argparse import ArgumentParser, ArgumentTypeError
from contextlib import suppress
from functools import partial
from itertools import islice, chain
import asyncio
import ipaddress
import re
import socket
import sys

try:
    import uvloop
    asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
except ImportError:
    # print("Life is better with uvloop")
    pass


PORTS = (
    "21-23 25 80 443 8080 8443 445 139",  # default ports to scan
    ' '  # delimiter
)


def as_completed(tasks, count: int=100):
    """
    Asynchronously iterates through tasks as they are completed.
    Superior to semaphore + asyncio.gather method because... it doesn't require a semaphore.
    Oh, and it also allows for an infinite/unbounded amount of concurrent tasks with a limited number of workers.

    Mostly CPU bound due to the tight while True loop. Very soft on memory even with a high amount of workers.
    """
    futs = [asyncio.ensure_future(task) for task in islice(tasks, 0, count)]

    @asyncio.coroutine
    def wrapped():
        while True:
            yield from asyncio.sleep(0)
            for fut in futs:
                if fut.done():
                    futs.remove(fut)
                    with suppress(StopIteration):
                        futs.append(asyncio.ensure_future(next(tasks)))
                    return fut.result()
    while futs:
        yield wrapped()


@asyncio.coroutine
def check_port(host, port: int, timeout: float):
    """
    Create a connection. If the connection establishes, report that the host:port is open.
portportportportssss
    :param host: a str or ipaddress module ip address.
    :param port: an integer between 1 and 65535.
    :param timeout: float value indiciating the connection timeout

    :return a 3-tuple containing the open indicator and the original host/port.
    """
    fut = asyncio.open_connection(str(host), port)
    is_open = False
    info = None
    try:
        reader, writer = yield from asyncio.wait_for(fut, timeout=timeout)
        # port is open
        is_open = True
        writer.write(b"\r\n\r\n")
        info = (yield from asyncio.wait_for(reader.read(4096), timeout=timeout)).decode("utf-8", "ignore").strip().replace("\r", "").replace("\n", "")
    except (asyncio.TimeoutError, ConnectionRefusedError, OSError):
        # ignore timeouts, disconnects, connection refused, etc...
        pass
    except Exception as e:
        # anything else, I probably want to know.
        print(type(e), e, sep="\n")
    finally:
        return is_open, host, port, info



@asyncio.coroutine
def app(networks, ports: list, timeout: float, conns: int, quiet: bool, only_open: bool, fmt_csv: bool):
    if quiet is False:
        print((
            "Network:     {}\n"
            "Ports:       {}\n"
            "Concurrency: {}\n"
            "Timeout:     {}\n"
            ).format(','.join(str(network) for network in networks), ','.join(map(str, ports)), conns, timeout))
    tasks = (
        check_port(host, port, timeout) \
                for network in networks \
                for host in ((network.network_address,) if network.num_addresses == 1 else network.hosts()) \
                for port in ports)
    fmt = "{},{},{}" if fmt_csv else "{:<16} {:<5} {:<6} {}"
    for task in as_completed(tasks, conns):
        is_open, host, port, info = yield from task
        if only_open is False or is_open:
            print(fmt.format(str(host), port, "open" if is_open else "closed", info))


def num_range(val):
    nums = re.match(r'(\d+)(?:-(\d+))?$', val)
    if not nums:
        raise ArgumentTypeError("'{}' is an invalid number.".format(val))
    beg = int(nums.group(1))
    end = int(nums.group(2) or beg)
    if end < beg:
        beg, end = end, beg
    return list(range(beg, end+1))


def multi_num_range(val, delimiter=' '):
    """wrapper for num_range to pass in a full string"""
    return [num_range(v) for v in val.split(delimiter) if v]


def net_or_host(val):
    try:
        return ipaddress.ip_network(val, strict=False)
    except:
        return ipaddress.ip_network(socket.gethostbyname(val), strict=False)


def main():
    ap = ArgumentParser()
    ap.add_argument("-n", "--net", type=net_or_host, nargs="+", required=True, help="CIDR for network to scan")
    ap.add_argument("-p", "--ports", nargs="+", type=num_range, default=multi_num_range(*PORTS), help="Ports to scan")
    ap.add_argument("-t", "--timeout", type=float, default=1.0, help="Timeout for connections.")
    ap.add_argument("-c", "--conns", type=int, default=100, help="Number of concurrent connections.")
    ap.add_argument("-q", "--quiet", action="store_true", help="Quiet output. Only show ports/statuses.")
    ap.add_argument("--open", action="store_true", help="Only show open ports")
    ap.add_argument("--csv", action="store_true", help="Output in csv format")
    args = ap.parse_args()
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(
            app(
                args.net,
                sorted(list(set(chain.from_iterable(args.ports)))),
                args.timeout,
                args.conns,
                args.quiet,
                args.open,
                args.csv,
            )
        )
    except KeyboardInterrupt:
        print("\nExiting...")
        pending = list(asyncio.Task.all_tasks())
        for task in pending:
            task.cancel()
    finally:
        loop.close()


if __name__ == "__main__":
    main()
