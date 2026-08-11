"""The side that has the destination: announces it once, proves what
reaches it, and answers a link."""

import sys
import time

import RNS


def spoken(message, packet):
    print("heard on the link:", message.decode(), flush=True)


def opened(link):
    print("link established", flush=True)
    link.set_packet_callback(spoken)


reticulum = RNS.Reticulum(configdir=sys.argv[1])
identity = RNS.Identity()
destination = RNS.Destination(
    identity, RNS.Destination.IN, RNS.Destination.SINGLE, "haskell", "check"
)
destination.set_proof_strategy(RNS.Destination.PROVE_ALL)
destination.set_link_established_callback(opened)
print(destination.hash.hex(), flush=True)

# Late enough that the node between is connected, and only once: a
# second announce would reach the other side by itself.
time.sleep(int(sys.argv[2]))
destination.announce(app_data=b"from the reference")
print("announced", flush=True)

while True:
    time.sleep(1)
