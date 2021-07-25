import json
import os
import argparse
from decimal import Decimal
from itertools import groupby
import scipy.stats
import numpy
import matplotlib.pyplot as plt
import sys
import matplotlib

# Make sure that we are using QT5
matplotlib.use('Qt5Agg')
import matplotlib.pyplot as plt
from PyQt5 import QtWidgets, QtCore
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.backends.backend_qt5agg import NavigationToolbar2QT as NavigationToolbar

class ScrollableWindow(QtWidgets.QMainWindow):
    def __init__(self, fig, ax, step=0.1):
        plt.close("all")
        if not QtWidgets.QApplication.instance():
            self.app = QtWidgets.QApplication(sys.argv)
        else:
            self.app = QtWidgets.QApplication.instance() 

        QtWidgets.QMainWindow.__init__(self)
        self.widget = QtWidgets.QWidget()
        self.setCentralWidget(self.widget)
        self.widget.setLayout(QtWidgets.QVBoxLayout())
        self.widget.layout().setContentsMargins(0,0,0,0)
        self.widget.layout().setSpacing(0)

        self.fig = fig
        self.ax = ax
        self.canvas = FigureCanvas(self.fig)
        self.canvas.draw()
        self.scroll = QtWidgets.QScrollBar(QtCore.Qt.Horizontal)
        self.step = step
        self.setupSlider()
        self.nav = NavigationToolbar(self.canvas, self.widget)
        self.widget.layout().addWidget(self.nav)
        self.widget.layout().addWidget(self.canvas)
        self.widget.layout().addWidget(self.scroll)

        self.canvas.draw()
        self.show()
        self.app.exec_()

    def setupSlider(self):
        self.lims = numpy.array(self.ax.get_xlim())
        self.scroll.setPageStep(self.step*100)
        self.scroll.actionTriggered.connect(self.update)
        self.update()

    def update(self, evt=None):
        r = self.scroll.value()/((1+self.step)*100)
        l1 = self.lims[0]+r*numpy.diff(self.lims)
        l2 = l1 +  numpy.diff(self.lims)*self.step
        self.ax.set_xlim(l1,l2)
        #print(self.scroll.value(), l1,l2)
        self.fig.canvas.draw_idle()


DEFAULT_MULTIPLIER = 100 #(in milliseconds)
#The expected round trip time when things are idle
EXPECTED_RTT = .8 #Decimal(0.0003309563566812180496615196195)

IP = "192.168.0.31"
IPV6 = "2601:5c0:c000:5310:deb:79a7:123b:ad33"

# Parse arguments
parser = argparse.ArgumentParser()
parser.add_argument("adversary_file")
parser.add_argument("victim_file")
parser.add_argument("-m", "--multiplier", type=int, default=DEFAULT_MULTIPLIER, help="Defines the interval with - int(MULTIPLIER * float(x[timestamp]))")
args = parser.parse_args()

multiplier = args.multiplier

# Open files
victim_file = open(args.victim_file)
victim_data = json.load(victim_file)
victim_file.close()

adversary_file = open(args.adversary_file)
adversary_data = json.load(adversary_file)
adversary_file.close()

# Extract the relevant fields
victim_packets = []
adversary_pings = {}

for item in victim_data:
    cleaned_item = item["_source"]["layers"]
    victim_packets.append(cleaned_item)
    
for item in adversary_data:
    cleaned_item = item["_source"]["layers"]
    adversary_pings[cleaned_item["frame.number"][0]] = cleaned_item

#Match response times with the originating pings
ping_times = []
ping_delays = []
for v in adversary_pings.values():
    if v.get("icmp.resptime"):
        if adversary_pings.get(v["icmp.resp_to"][0]):
            ping_times.append(float(adversary_pings[v["icmp.resp_to"][0]]["frame.time_epoch"][0]))
            ping_delays.append(float(v["icmp.resptime"][0]))
       
print(len(ping_times))

#Group packets by window
get_key = lambda x: int(multiplier * float(x["frame.time_epoch"][0]))

#Sort packets
victim_packets = sorted(victim_packets, key=get_key)

times = []
sizes = []
incomings = []

intervals = {}
for k, g in groupby(victim_packets, get_key):
    cur_interval = {"interval": k, "packets": list(g)}
    cur_interval["size"] = sum(map(lambda x: int(x["frame.len"][0]), cur_interval["packets"]))
    cur_interval["incoming"] = sum(map(lambda x: int(x["frame.len"][0]), filter(lambda x: (x.get("ip.dst") and x["ip.dst"][0] == IP) or (x.get("ipv6.dst") and x["ipv6.dst"][0] == IPV6), cur_interval["packets"])))
    intervals[k] = cur_interval
    
    #fill in empty intervals
    while(times and k - (times[-1] * multiplier) > 1):
        times.append(times[-1] + (1.0 / multiplier))
        sizes.append(0)
        incomings.append(0)
    
    times.append(k / float(multiplier))
    sizes.append(cur_interval["size"])
    incomings.append(cur_interval["incoming"])

# Shift timestamps to start at 0
start_time = min(times)

print(start_time)
times = [time - start_time for time in times]
ping_times = [time - start_time for time in ping_times]

# Print correlation
#print("Pearson Correlation: " + str(scipy.stats.pearsonr(sizes, ping_)))

fig, ax1 = plt.subplots()
color = 'tab:red'
ax1.set_xlabel('Timestamp')
ax1.set_ylabel('bytes', color=color)  
ax1.plot(times, sizes, color=color, marker='.')
ax1.plot(times, incomings, color = 'tab:brown')
ax1.tick_params(axis='y', labelcolor=color)

ax2 = ax1.twinx()
color = 'tab:blue'
ax2.set_ylabel('Ping RTT (milliseconds)', color=color)
ax2.plot(ping_times, ping_delays, color=color)
ax2.tick_params(axis='y', labelcolor=color)

fig.tight_layout()  # otherwise the right y-label is slightly clipped
#plt.show()


# pass the figure to the custom window
a = ScrollableWindow(fig,ax1, .01)
