"""The side that talks to the node itself: a path it asks for, a packet
it proves, a link it answers, the requests it serves, and a resource it
takes in."""

import os
import sys
import time

import RNS

proved = []
onlink = []
answers = []
concluded = []

reticulum = RNS.Reticulum(configdir=sys.argv[1])
wanted = bytes.fromhex(sys.argv[2])

# The node dials this side every few seconds, and the announce it made
# at startup is spent by now.
time.sleep(8)
RNS.Transport.request_path(wanted)
for _ in range(30):
    time.sleep(1)
    if RNS.Transport.has_path(wanted):
        break
print("has path:", RNS.Transport.has_path(wanted), flush=True)
if not RNS.Transport.has_path(wanted):
    sys.exit(1)

identity = RNS.Identity.recall(wanted)
destination = RNS.Destination(
    identity, RNS.Destination.OUT, RNS.Destination.SINGLE, "haskell", "check"
)

receipt = RNS.Packet(destination, b"one packet").send()
receipt.set_delivery_callback(lambda taken: proved.append(True))
for _ in range(20):
    time.sleep(0.5)
    if proved:
        break
print("packet proved:", bool(proved), flush=True)

link = RNS.Link(destination)
for _ in range(40):
    time.sleep(0.5)
    if link.status == RNS.Link.ACTIVE:
        break
print("link active:", link.status == RNS.Link.ACTIVE, flush=True)
if link.status != RNS.Link.ACTIVE:
    sys.exit(1)

receipt = RNS.Packet(link, b"over the link").send()
receipt.set_delivery_callback(lambda taken: onlink.append(True))
for _ in range(20):
    time.sleep(0.5)
    if onlink:
        break
print("link packet proved:", bool(onlink), flush=True)


def answered(receipt):
    answers.append(receipt.response)


link.request("echo", data=b"say it back", response_callback=answered)
for _ in range(20):
    time.sleep(0.5)
    if answers:
        break
print("response:", answers[0] if answers else None, flush=True)

# Longer than one packet on the link holds, so it goes as a resource,
# and the path it names answers with a length that fits in one.
long = os.urandom(4000)
link.request("length", data=long, response_callback=answered)
for _ in range(60):
    time.sleep(0.5)
    if len(answers) > 1:
        break
print("request as resource:", answers[1] if len(answers) > 1 else None, flush=True)

RNS.Resource(os.urandom(3000), link, callback=lambda resource: concluded.append(resource))
for _ in range(60):
    time.sleep(0.5)
    if concluded:
        break
print("resource concluded:", bool(concluded), flush=True)

link.teardown()
time.sleep(2)
