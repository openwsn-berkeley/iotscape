# Python
import time
import struct
import threading
import Queue
import traceback
import os
# third-party


#============================ helpers =========================================


#============================ classes =========================================

class Postprocessing():
    
    # global variables
    OFFSET_PACKET_DESTINATION          = 22
    OFFSET_PACKET_LATITUDE             = 11
    OFFSET_PACKET_LONGITUDE            = 15
    PCAP_GLOBALHEADER_LEN              = 24 # 4+2+2+4+4+4+4
    PCAP_PACKETHEADER_LEN              = 16 # 4+4+4+4
    BEAMLOGIC_HEADER_LEN               = 20 # 1+8+1+1+4+4+1
    BEAMLOGIC_OFFSET_TIME              = 3600
    PCAP_FILES_PATH                    = 'C:\Users\clopezlo\Desktop\iotscapeData' 
    NOISY_MOTE_DESTINATION             = '\x9d\x9d'
    FILENAME_OUTPUT                    = 'processed_packets.pcap'

    def __init__(self, gps):
    
        # store params
        self.gps             = gps

        # local variables
        self.rxBuffer                  = []
        self.packet                    = []
        self.globalHeader              = []
        self.doneReceivingGlobalHeader = False
        self.doneReceivingPacketHeader = False
        self.doneWritingGlobalHeader   = False
        self.outfile                   = open(self.FILENAME_OUTPUT,'wb')

        # start the class
        self.name                      = 'Postprocessing'
        self.run()
    
    def run(self):
        
        # read data from all pcap files
        for file in os.listdir(self.PCAP_FILES_PATH):
            if file.endswith('.pcap'):
                self.filePath   = os.path.join(self.PCAP_FILES_PATH, file)
                with open(self.filePath, 'rb') as fileInProcess:
                    print 'Processing {0}'.format(self.filePath)
                    while True:
                        try:
                            b = ord(fileInProcess.read(1))
                        except:
                            break
                        self._newByte(b) 
                    
                    # close file and reset variables
                    fileInProcess.close()
                    self.doneReceivingGlobalHeader = False
                    self.doneReceivingPacketHeader = False
                    self.rxBuffer                  = []

    #======================== public ==========================================

    #======================== private =========================================
    def _newByte(self, b):
        
        self.rxBuffer += [b]
        
        # PCAP global header
        if   not self.doneReceivingGlobalHeader:
            if len(self.rxBuffer) == self.PCAP_GLOBALHEADER_LEN:
                self.doneReceivingGlobalHeader       = True
                self.globalHeader                    = self.rxBuffer
                self.rxBuffer                        = []

        # PCAP packet header
        elif not self.doneReceivingPacketHeader:
            if len(self.rxBuffer) == self.PCAP_PACKETHEADER_LEN:
                self.doneReceivingPacketHeader       = True
                self.packetHeader                    = self._parsePcapPacketHeader(self.rxBuffer)
                assert self.packetHeader['incl_len'] == self.packetHeader['orig_len']
                self.packet                          = self.rxBuffer
                self.rxBuffer                        = []
                
        # PCAP packet bytes
        else:
            if len(self.rxBuffer) == self.packetHeader['incl_len']:
                self.doneReceivingPacketHeader       = False
                self._newFrame(self.rxBuffer)
                self.rxBuffer                        = []
                
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
        ) = struct.unpack('<IIII', ''.join([chr(b) for b in header]))

        return returnVal

    def _newFrame(self, frame):
        
        self.packetDestination    = ''.join([chr(b) for b in frame[self.OFFSET_PACKET_DESTINATION:self.OFFSET_PACKET_DESTINATION+2]])
        if self.packetDestination != self.NOISY_MOTE_DESTINATION:
            self.timestamp        = int(self.packetHeader['ts_sec'])-self.BEAMLOGIC_OFFSET_TIME 
            while True:
                try:
                    self.latitude, self.longitude     = self.gps.getLocation(self.timestamp)
                    break
                except:
                    self.timestamp                    += 1
            self.writeBytes(frame)

    def writeBytes(self, frame):
        
        # write global header
        if   not self.doneWritingGlobalHeader:
            self.outfile.write(''.join([chr(b) for b in self.globalHeader]))
            self.doneWritingGlobalHeader = True
        
        # convert to bytes
        bytesHeader        = ''.join([chr(b) for b in self.packet])
        bytesPacketInitial = ''.join([chr(b) for b in frame[:self.OFFSET_PACKET_LATITUDE]])
        bytesLatitude      = ''.join([chr(b) for b in [40,0,0,0]])
        bytesLongitude     = ''.join([chr(b) for b in [40,0,0,0]])
        bytesPacketFinal   = ''.join([chr(b) for b in frame[self.OFFSET_PACKET_LATITUDE+8:]])
        bytesFrame         = bytesHeader+bytesPacketInitial+bytesLatitude+bytesLongitude+bytesPacketFinal
        
        # write bytes 
        self.outfile.write(bytesFrame)

class Gps():

    # global variables
    GPS_FILES_PATH         = 'C:\Users\clopezlo\Desktop\iotscapeData'
    GPS_OFFSET_TIME        = 7200 # 2 hours (3600s*2)
    
    def __init__(self):
        
        # local variables
        self.gpsData       = []
        
        # start the class
        self.name          = 'Gps'
        self.run()

    def run(self):
        
        # list: gpsData (timestamp, latitude, longitude)
        for file in os.listdir(self.GPS_FILES_PATH):
            if file.endswith('.log'):
                self.filePath    = os.path.join(self.GPS_FILES_PATH, file)
                self.date        = file.split('-')[0]
                with open(self.filePath, 'r') as fileInProcess:
                    for line in fileInProcess:
                        data = line.split(",")
                        if data[0] == "$GPGLL":
                            if data[1]=='':
                                continue
                            self.timestamp, self.latitude, self.longitude = self.getGpsInfo(data)
                            self.gpsData.append([self.timestamp, self.latitude, self.longitude])
                            
    #======================== public ==========================================

    #======================== private =========================================
    def getGpsInfo(self, data):
        lat         = data[1]
        lat         = int(lat[:2])+float(lat[2:])/60
        latDir      = data[2]
        long        = data[3]
        long        = int(long[:3])+float(long[3:])/60
        longDir     = data[4]

        if latDir == 'S':
            lat     = -lat

        if longDir == 'W':
            long    = -long
            
        gpsTime     = str(data[5].split(".")[0])
        dateTime    = self.date + gpsTime
        timestamp   = time.mktime(time.strptime(dateTime, '%Y%m%d%H%M%S'))+ self.GPS_OFFSET_TIME
        return timestamp, lat, long

        
    def getLocation(self, timestamp):
        for row in self.gpsData:
            if row[0] == timestamp:
                return row[1], row[2]

#============================ main ============================================

def main():    
    # start 
    gps                      = Gps()
    postprocessing           = Postprocessing(gps)
if __name__ == "__main__":
    main()