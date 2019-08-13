# Python
import time
import struct
import glob
# third-party

#============================ helpers =========================================

#============================ defines =========================================

#============================ classes =========================================

class GpsLog():

    def __init__(self):
        
        # local variables
        self.gpsData       = []
        
        # parse GPS log files
        for filename in glob.glob('*.log'):
            print 'parsing {0}'.format(filename)
            with open(filename, 'r') as f:
                for line in f:
                    if line.startswith('$GPRMC'):
                        
                        # parse
                        elems          = line.split(',')
                        nowTime        = elems[1]
                        lat            = elems[3]
                        lat_heading    = elems[4]
                        lon            = elems[5]
                        lon_heading    = elems[6]
                        nowDate        = elems[9]
                        
                        # skip line if no position acquired
                        if lat=='':
                            continue
                        
                        # timestamp
                        ts_string      = int(nowDate+nowTime.split('.')[0])
                        ts_string      = '{0} GMT'.format(ts_string)
                        timestamp      = int(time.mktime(time.strptime(ts_string, '%d%m%y%H%M%S %Z'))+3600)
                        
                        # location
                        location       =  self._computeLatLon(lat,lat_heading,lon,lon_heading)

                        # store
                        self.gpsData  += [(timestamp,location)]

    #======================== public ==========================================

    def getLocationAtTs(self,ts):
        for (timestamp,location) in self.gpsData:
            if timestamp == ts:
                return location
    
    #======================== private =========================================
    
    def _computeLatLon(self,lat,lat_heading,lon,lon_heading):
        outlat          = int(lat[:2])+float(lat[2:])/60
        if lat_heading == 'S':
            outlat      = -outlat
        outlon          = int(lon[:3])+float(lon[3:])/60
        if lon_heading == 'W':
            outlon      = -outlon
        return (outlat,outlon)

class PcapLog(object):
    
    # global variables
    OFFSET_PACKET_LATITUDE             = 11
    OFFSET_PACKET_LONGITUDE            = 15
    PCAP_GLOBALHEADER_LEN              = 24 # 4+2+2+4+4+4+4
    PCAP_PACKETHEADER_LEN              = 16 # 4+4+4+4
    BEAMLOGIC_HEADER_LEN               = 20 # 1+8+1+1+4+4+1
    PCAP_FILES_PATH                    = 'C:\Users\clopezlo\Desktop\iotscapeData' 
    FILENAME_OUTPUT                    = 'processed_packets.pcap'
    EXTRACT_MY_BEACON_DESTINATIONPAN   = ''.join([chr(b) for b in [157]*2])
    EXTRACT_MY_BEACON_DESTINATION      = ''.join([chr(b) for b in [157]*8])
    EXTRACT_MY_BEACON_SOURCEPAN        = ''.join([chr(b) for b in [157]*2])
    EXTRACT_MY_BEACON_SOURCE           = ''.join([chr(b) for b in [157]*2])

    def __init__(self, gpslog):
    
        # store params
        self.gpslog                    = gpslog

        # local variables
        self.outfile                   = open(self.FILENAME_OUTPUT,'wb')
        
        with open(self.FILENAME_OUTPUT,'wb') as fout:
            # read data from all pcap files
            doneWritingGlobalHeader   = False
            for filename in glob.glob('2*.pcap'):
                print 'parsing {0}'.format(filename)
                with open(filename, 'rb') as f:
                    # global header
                    globalHeader = f.read(self.PCAP_GLOBALHEADER_LEN)
                    
                    # write global header                   
                    if not doneWritingGlobalHeader:
                        fout.write(globalHeader)
                        doneWritingGlobalHeader = True
                        
                    while True:
                        try:
                            # read header
                            h  = f.read(self.PCAP_PACKETHEADER_LEN)
                            ph = self._parsePcapPacketHeader(h)
                            
                            # read packet
                            p = f.read(ph['incl_len'])
                        except:
                            break
                        
                        # skip incomplete packets
                        if ph['incl_len']!=len(p):
                            continue
                            
                        # skip our own beacons
                        if p[22:22+2]==self.EXTRACT_MY_BEACON_DESTINATIONPAN or p[24:24+8]==self.EXTRACT_MY_BEACON_DESTINATION or p[32:32+2]==self.EXTRACT_MY_BEACON_SOURCEPAN or p[34:34+2]==self.EXTRACT_MY_BEACON_SOURCE:
                            continue
                        
                        # get location
                        ts = ph['ts_sec']-3600
                        ts1 = min([i[0] for i in self.gpslog.gpsData], key=lambda x:abs(x-ts))
                        location = self.gpslog.getLocationAtTs(ts1)
                        if abs(ts1-ts)>120:
                            print "WARNING: Nearest GPS signal with {0} seconds difference".format(abs(ts1-ts))
                        
                        p = [ord(b) for b in p]
                        
                        # write location
                        p[11:11+4] = [ord(b) for b in struct.pack('>f',location[0])]
                        p[15:15+4] = [ord(b) for b in struct.pack('>f',location[1])]

                        # write header
                        fout.write(h)
                        
                        # write packet
                        fout.write(''.join([chr(b) for b in p]))

    #======================== public ==========================================

    #======================== private =========================================
    
    def _parsePcapPacketHeader(self, header):
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

        assert len(header) == self.PCAP_PACKETHEADER_LEN

        returnVal = {}
        (
            returnVal['ts_sec'],
            returnVal['ts_usec'],
            returnVal['incl_len'],
            returnVal['orig_len'],
        ) = struct.unpack('<IIII', header)

        return returnVal

#============================ main ============================================

def main():    
    # start 
    gpslog    = GpsLog()
    pcapLog   = PcapLog(gpslog)

if __name__ == "__main__":
    main()