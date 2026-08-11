"""The side the node dials: a destination it holds, the link and the
packets it answers, the two paths it serves, the resource it takes in,
and the close the node writes when it is done."""

import sys
import time

import RNS

reticulum = RNS.Reticulum(configdir=sys.argv[1])
identity = RNS.Identity()
destination = RNS.Destination(
    identity, RNS.Destination.IN, RNS.Destination.SINGLE, "python", "hold"
)
destination.set_proof_strategy(RNS.Destination.PROVE_ALL)


def took(plain, packet):
    print("took", plain, flush=True)


def concluded(resource):
    print("resource concluded:", len(resource.data.read()), flush=True)


def gone(link):
    print("link closed", flush=True)


def established(link):
    link.set_resource_strategy(RNS.Link.ACCEPT_ALL)
    link.set_packet_callback(took)
    link.set_resource_concluded_callback(concluded)
    link.set_link_closed_callback(gone)
    print("link established", flush=True)


def echo(path, data, request_id, link_id, remote_identity, requested_at):
    return data


def length(path, data, request_id, link_id, remote_identity, requested_at):
    return str(len(data)).encode("utf-8")


destination.set_link_established_callback(established)
destination.register_request_handler(
    "echo", response_generator=echo, allow=RNS.Destination.ALLOW_ALL
)
destination.register_request_handler(
    "length", response_generator=length, allow=RNS.Destination.ALLOW_ALL
)

print(destination.hash.hex(), flush=True)

# The node dials this side a few seconds in, and what it learns the path
# from is one of these.
for _ in range(60):
    destination.announce()
    time.sleep(4)
