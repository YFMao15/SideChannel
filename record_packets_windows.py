import sys
import os
import json
import pyshark as ps

# Params for packet recording
# testing on windows system
interface = '\\Device\\NPF_{B356A9C5-88DF-4570-92F7-405AF9B3CA2B}'
output = "adversary1"
packet_count = 200
timeout = 1000
capture = ps.LiveCapture(interface = interface)
capture.sniff(packet_count = packet_count, timeout = timeout)

print(len(capture))
