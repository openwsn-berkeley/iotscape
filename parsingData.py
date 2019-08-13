import subprocess
from matplotlib import pyplot as plt
from manuf import manuf
import pandas as pd
import numpy as np


channels  = []
protocols = []
security  = []
vendors   = []

protocolsDB          = [['siteanalyzer:wpan:data', 'IEEE 802.15.4'],
                        ['siteanalyzer:wpan:lwm:data', 'LWMESH'], 
                        ['siteanalyzer:wpan:6lowpan:ipv6', '6LoWPAN'],
                        ['siteanalyzer:wpan:zbee_nwk:zbee_aps', 'ZigBee'],
                        ['siteanalyzer:wpan:6lowpan:ipv6:udp:mle:data', '6LoWPAN'],
                        ['siteanalyzer:wpan', 'IEEE 802.15.4'],
                        ['siteanalyzer:wpan:6lowpan:data', '6LoWPAN'],
                        ['siteanalyzer:wpan:zbee_nwk:data', 'ZigBee'],
                        ['siteanalyzer:wpan:6lowpan', '6LoWPAN'],
                        ['siteanalyzer:wpan:zbee_nwk', 'ZigBee']]


myCmd = 'tshark -T fields -e frame.number -e wtap_encap.Channel -e frame.protocols -e wpan.security -e wpan.src64 -r C:\Users\clopezlo\Desktop\iotscape\processed_packets.pcap'

p = subprocess.check_output(myCmd,stderr=subprocess.STDOUT,shell=True, cwd='C:\Program Files\Wireshark')

vendorsDB = manuf.MacParser(update=True)
for line in p.splitlines():
    data = line.split()
    
    channels.append(int(data[1]))
    
    for x in protocolsDB:
        if x[0] == data[2]:
            protocols.append(x[1])
    
    security.append(data[3])

    
    try:
        vendors.append(str(vendorsDB.get_manuf(data[4][0:8])))
    except:
        vendors.append(str(None))
    
print set(channels)
print set(protocols)
print set(security)
print set(vendors)

def autolabel(rects):
    """Attach a text label above each bar in *rects*, displaying its height."""
    for rect in rects:
        height = rect.get_height()
        ax.annotate('{}'.format(height),
                    xy=(rect.get_x() + rect.get_width() / 2, height),
                    xytext=(0, 1),  # 3 points vertical offset
                    textcoords="offset points",
                    ha='center', va='bottom')
# Plot Security chart
group_names = ['True', 'False']
counts = pd.Series([security.count('0'), security.count('1')], index=['', '']) 
index=['False', 'True']
colors = ['#0071C6', '#191970']
counts.plot(kind='pie', fontsize=10, colors=colors, autopct='%.1f%%')
plt.title("Security Enabled")
plt.axis('equal')
plt.ylabel('')
plt.legend(labels=index, loc="best")
plt.show()

######Protocols########
labels = set(protocols)
nPackets = []
for b in labels:
    nPackets += [protocols.count(b)]
x = np.arange(len(labels))  # the label locations
width = 0.35  # the width of the bars
fig, ax = plt.subplots()
rects1 = ax.bar(x, nPackets, width)
# Add some text for labels, title and custom x-axis tick labels, etc.
ax.set_ylabel('No. Packets')
ax.set_title('Protocols')
ax.set_xticks(x)
ax.set_xticklabels(labels)
ax.legend()
autolabel(rects1)
fig.tight_layout()
plt.show()

######Channels########
labels = set(channels)
nPackets = []
for b in labels:
    nPackets += [channels.count(b)]
x = np.arange(len(labels))  # the label locations
width = 0.35  # the width of the bars
fig, ax = plt.subplots()
rects1 = ax.bar(x, nPackets, width)
# Add some text for labels, title and custom x-axis tick labels, etc.
ax.set_ylabel('No. Packets')
ax.set_title('Channels')
ax.set_xticks(x)
ax.set_xticklabels(labels)
ax.legend()
autolabel(rects1)
fig.tight_layout()
plt.show()

######Vendors########
labels = set(vendors)
labels.remove('None')
nPackets = []
for b in labels:
    nPackets += [vendors.count(str(b))]
x = np.arange(len(labels))  # the label locations
width = 0.35  # the width of the bars
fig, ax = plt.subplots()
rects1 = ax.bar(x, nPackets, width)
# Add some text for labels, title and custom x-axis tick labels, etc.
ax.set_ylabel('No. Packets')
ax.set_title('Vendors')
ax.set_xticks(x)
ax.set_xticklabels(labels)
plt.xticks(rotation=90)
ax.legend()
autolabel(rects1)
fig.tight_layout()
plt.show()








