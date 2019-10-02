"""
Simple CLI invocation of the YAPPS port scanner
"""

from argparse import ArgumentParser
from contextlib import suppress
import asyncio
import sys
import time
import traceback

from yapps import Scanner, ScanInfo, ScanState, ArgTypes


def show_info(info: ScanInfo, verbose: bool = False):
    """
    Displaying ScanInfo object in a nice format
    :param info: the ScanInfo object provided by YAPPS
    :param verbose: show port state even if it isn't open
    :return:
    """
    if verbose or info.state == ScanState.OPEN:
        print(f"{info.host:<16} {info.state.name:<8} {info.port:<6} {info.banner or ''}")


async def run(args):
    ports = ' '.join(args.ports)
    async with Scanner(workers=args.workers, timeout=args.timeout, banner=args.banner) as scanner:
        start = time.time()
        for host in (args.host or []):
            await scanner.check_host(host, ports)
        for net in (args.net or []):
            await scanner.check_net(net, ports)
        async for result in scanner:
            show_info(result, args.verbose)
    print(f"Took {time.time() - start:0.3f} seconds")


def main():
    ap = ArgumentParser("yapps")
    ap.add_argument("--host", "-H", type=ArgTypes.host, nargs="+", help="IP Address")
    ap.add_argument("--net", "-N", type=ArgTypes.net, nargs="+", help="Network/CIDR")
    ap.add_argument("--ports", "-p", type=str, nargs="+", required=True, help="Ports to which clients will connect")
    ap.add_argument("--verbose", "-v", action="store_true", help="Verbose output")
    ap.add_argument("--banner", "-b", action="store_true", help="Retrieve banner from remote service")
    ap.add_argument("--timeout", "-t", type=float, default=3.0, help="Connection timeout")
    ap.add_argument("--workers", "-w", type=int, default=100, help="Number of concurrent async workers")

    args = ap.parse_args()
    if not (args.host or args.net):
        ap.error("Either --host or --net is required.")
        sys.exit(1)

    if sys.platform == 'win32':
        asyncio.set_event_loop(asyncio.ProactorEventLoop())
    else:
        with suppress(ImportError):
            import uvloop
            asyncio.set_event_loop_policy(uvloop.EventLoopPolicy())
    loop = asyncio.get_event_loop()
    try:
        loop.run_until_complete(run(args))
    except Exception as e:
        traceback.print_exc()
        print(f"The error: {type(e)}")


if __name__ == "__main__":
    main()
