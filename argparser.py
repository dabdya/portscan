import argparse


def create_argparser():
    argparser = argparse.ArgumentParser()
    argparser.add_argument("--timeout", type=float, default=1)
    argparser.add_argument("--num-threads", "-j", type=int, default=1)
    argparser.add_argument("--verbose", "-v", action="store_true")
    argparser.add_argument("--guess", "-g", action="store_true")
    argparser.add_argument("IP_ADDRESS")

    argparser.add_argument(
        "proto", nargs="*",
        help="{tcp|udp}[/[port|port-port], ...]")

    return argparser
