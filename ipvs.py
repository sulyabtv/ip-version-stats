from argparse import Namespace, ArgumentParser
import sys

def get_parser() -> ArgumentParser:
    parser = ArgumentParser( description="IP-Version-Stats: A tool to monitor network traffic and obtain IPv4 vs IPv6 traffic statistics" )

    # Arguments
    parser.add_argument( '-i', '--interface', dest='interface',
                         default=None, type=str,
                         help="Name (eg: eth0) of the interface on which to monitor traffic. "
                              "If no interface name is provided, traffic will be monitored on all interfaces." )

    return parser

def main():
    parser = get_parser()
    args = parser.parse_args()

if __name__ == "__main__":
    main()