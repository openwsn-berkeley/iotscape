# Python
import json
import struct

OFFSET_PACKET_LATITUDE             = 11
OFFSET_PACKET_LONGITUDE            = 15
PCAP_GLOBALHEADER_LEN              = 24 # 4+2+2+4+4+4+4
PCAP_PACKETHEADER_LEN              = 16 # 4+4+4+4
BEAMLOGIC_HEADER_LEN               = 20 # 1+8+1+1+4+4+1

def _parsePcapPacketHeader(header):
        """
        Parse a PCAP packet header
        Per https://wiki.wireshark.org/Development/LibpcapFileFormat:
        typedef struct pcaprec_hdr_s {
            guint32 ts_sec;         /* timestamp seconds */
            guint32 ts_usec;        /* timestamp microseconds */
            guint32 incl_len;       /* number of octets of packet saved in file */
            guint32 orig_len;       /* actual length of packet */
        } pcaprec_hdr_t;
        """

        assert len(header) == PCAP_PACKETHEADER_LEN

        returnVal = {}
        (
            returnVal['ts_sec'],
            returnVal['ts_usec'],
            returnVal['incl_len'],
            returnVal['orig_len'],
        ) = struct.unpack('<IIII', header)

        return returnVal

# geoJSON structure

data = {
  "type": "FeatureCollection",
  "features": []
}

packetId = 1

# read data from pcap file
with open('processed_packets.pcap', 'rb') as f:

    # global header
    globalHeader = f.read(PCAP_GLOBALHEADER_LEN)
    
    while True:
        try:
            # read header
            h  = f.read(PCAP_PACKETHEADER_LEN)
            ph = _parsePcapPacketHeader(h)

            # read packet
            p = f.read(ph['incl_len'])
        except:
            break
            
        p = [ord(b) for b in p]
        
        # get location
        locationBytes = ''.join([chr(b) for b in p[11:11+8]])
        location = {}
        (
            location['latitude'],
            location['longitude']
        )= struct.unpack('>ff', locationBytes) 
        
        # append new point 
        data['features'].append({
              "type": "Feature",
              "properties": { 
              "marker-symbol": "",
              "marker-color": "#0000ff", # RGB(HEX) red -> "#ff0000", green -> "#00ff00", blue -> "#0000ff"
              "marker-size": "small",
              "title": str(packetId)
              },
              "geometry": {
                "type": "Point",
                "coordinates": [
                  location['longitude'],
                  location['latitude']
                ]
              }
            })
        
        packetId+=1

# writing JSON object# 
with open('packetsLocation.json', 'w') as f:   
    json.dump(data, f)