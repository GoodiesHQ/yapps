"""
Parser and argument type verification
"""

from argparse import ArgumentTypeError
from typing import List
import ipaddress
import itertools
import re

__all__ = [
    "ArgTypes",
]


class ArgTypes:
    """
    Argument types for CLI parameters
    """

    @staticmethod
    def host(address: str) -> str:
        """
        Verify a host IPv4 or IPv6 address
        :param address: an IPv4/IPv6 address
        :return: address if valid
        :raises: ArgumentTypeError if the IP address is invalid
        """
        try:
            ipaddress.ip_address(address)
        except ValueError:
            raise ArgumentTypeError(f"Invalid Host Address '{address}'")
        return address

    @staticmethod
    def net(address: str) -> str:
        """
        Verify an IPv4 or IPv6 network range in CIDR notation
        :param address: an IPv4/IPv6 CIDR network
        :return: address if valid
        :raises: ArgumentTypeError if the network is invalid
        """
        try:
            ipaddress.ip_network(address, strict=False)
        except ValueError:
            raise ArgumentTypeError(f"Invalid Network '{address}'")
        return address

    @staticmethod
    def num_range(value: str) -> List[int]:
        """
        Given a string representation, parse for a single integer value or a
        range of values indicated by a dash
        :param value: string representation of a numerical value or range (ex: "80" or "22-25")
        :return: a list of one or more integer values indicated by `value`
        :raises: ArgumentTypeError upon invalid value(s) provided
        """
        nums = re.match(r'(\d+)(?:-(\d+))?$', value)
        if not nums:
            raise ArgumentTypeError("Invalid numerical range: {}".format(value))
        beg = int(nums.group(1))
        end = int(nums.group(2) or beg)
        if end < beg:
            beg, end = end, beg
        return list(range(beg, end + 1))

    @staticmethod
    def multi_num_range(value: str, delimiter: str = ' ') -> List[int]:
        nums = (ArgTypes.num_range(part) for part in value.split(delimiter) if part)
        return list(sorted(set(itertools.chain.from_iterable(nums))))
