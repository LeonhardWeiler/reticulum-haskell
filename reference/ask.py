"""The side that has nothing: asks for the path, sends one packet, and
opens a link over whatever answered."""

import sys
import time

import RNS

delivered = []

reticulum = RNS.Reticulum(configdir=sys.argv[1])
wanted = bytes.fromhex(sys.argv[2])

# The node between dials this side every few seconds, and the announce
# it holds is spent by now.
time.sleep(8)
print("has path before asking:", RNS.Transport.has_path(wanted), flush=True)

RNS.Transport.request_path(wanted)
for _ in range(30):
    time.sleep(1)
    if RNS.Transport.has_path(wanted):
        print("has path: True hops:", RNS.Transport.hops_to(wanted), flush=True)
        break
else:
    print("has path: False", flush=True)
    sys.exit(1)

identity = RNS.Identity.recall(wanted)
destination = RNS.Destination(
    identity, RNS.Destination.OUT, RNS.Destination.SINGLE, "haskell", "check"
)

receipt = RNS.Packet(destination, b"one packet").send()
receipt.set_delivery_callback(lambda taken: delivered.append(True))
for _ in range(20):
    time.sleep(0.5)
    if delivered:
        break
print("packet proved:", bool(delivered), flush=True)

link = RNS.Link(destination)
for _ in range(40):
    time.sleep(0.5)
    if link.status == RNS.Link.ACTIVE:
        break
print("link active:", link.status == RNS.Link.ACTIVE, flush=True)

if link.status == RNS.Link.ACTIVE:
    RNS.Packet(link, b"over the link").send()
    time.sleep(3)
