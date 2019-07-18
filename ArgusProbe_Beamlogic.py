"""
Argus probe for the Beamlogic Site Analyzer Lite
http://www.beamlogic.com/products/802154-site-analyzer.aspx
"""

import time
import struct
import socket
import threading
import json
import traceback
import datetime
import winsound
import re
import serial
#import ArgusVersion

#============================ helpers =========================================


def currentUtcTime():
    return time.strftime("%a, %d %b %Y %H:%M:%S UTC", time.gmtime())


def logCrash(threadName, err):
    output  = []
    output += ["============================================================="]
    output += [currentUtcTime()]
    output += [""]
    output += ["CRASH in Thread {0}!".format(threadName)]
    output += [""]
    output += ["=== exception type ==="]
    output += [str(type(err))]
    output += [""]
    output += ["=== traceback ==="]
    output += [traceback.format_exc()]
    output  = '\n'.join(output)

    print(output)

#============================ classes =========================================


class RxSnifferThread(threading.Thread):
    """
    Thread which attaches to the sniffer and parses incoming frames.
    """

    PCAP_GLOBALHEADER_LEN    = 24 # 4+2+2+4+4+4+4
    PCAP_PACKETHEADER_LEN    = 16 # 4+4+4+4
    BEAMLOGIC_HEADER_LEN     = 20 # 1+8+1+1+4+4+1
    PIPE_SNIFFER             = r'\\.\pipe\analyzer'
    OUTPUT                   = 'beamlogic'+time.strftime('%Y%m%d-%Hh%Mm%Ss')+'.pcap'
    FREQUENCY                = 3500
    DURATION                 = 50
    

    def __init__(self):

        # local variables
        self.dataLock                  = threading.Lock()
        self.rxBuffer                  = []
        self.doneReceivingGlobalHeader = False
        self.doneReceivingPacketHeader = False
        self.line                      = []
        self.outfile                   = open(self.OUTPUT,'wb')
        self.counter                   = 0
        self.serial                    = serial.Serial('COM28',9600)
                   

        # start the thread
        threading.Thread.__init__(self)
        self.name            = 'RxSnifferThread'
        self.start()

    def run(self):
        try:
            time.sleep(1)  # let the banners print
            while True:
                    try:
                        with open(self.PIPE_SNIFFER, 'rb') as sniffer:
                            while True:
                                    b = ord(sniffer.read(1))
                                    self._newByte(b)
                                                
                    except IOError:
                        print ("WARNING: Could not read from pipe at \"{0}\".".format(
                            self.PIPE_SNIFFER
                        ))
                        print ("Is SiteAnalyzerAdapter running?")
                        time.sleep(1)
        except Exception as err:
            logCrash(self.name, err)

    #======================== public ==========================================

    #======================== private =========================================

    def _newByte(self, b):
        """
        Just received a byte from the sniffer
        """
        with self.dataLock:
            self.rxBuffer += [b]
            # PCAP global header
            if   not self.doneReceivingGlobalHeader:
                if len(self.rxBuffer) == self.PCAP_GLOBALHEADER_LEN:
                    self.doneReceivingGlobalHeader    = True
                    self.outfile.write(''.join([chr(b) for b in self.rxBuffer]))
                    self.rxBuffer                     = []

            # PCAP packet header
            elif not self.doneReceivingPacketHeader:
                if len(self.rxBuffer) == self.PCAP_PACKETHEADER_LEN:
                    self.doneReceivingPacketHeader    = True
                    self.line                         = []
                    self.packetHeader                 = self._parsePcapPacketHeader(self.rxBuffer)
                    assert self.packetHeader['incl_len'] == self.packetHeader['orig_len']
                    self.line                         += self.rxBuffer
                    #self.line                         += [b for b in self.rxBuffer]
                    self.rxBuffer                     = []
                    
            # PCAP packet bytes
            else:
                if len(self.rxBuffer) == self.packetHeader['incl_len']:
                    self.doneReceivingPacketHeader    = False
                    self._newFrame(self.rxBuffer)
                    self.rxBuffer                     = []

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

    def float2hex(self, n):
        
        if n == 0.0:
            returnValue = b"\x00\x00\x00\x00"
            return str(returnValue)
        
        returnValue = hex(struct.unpack('<I', struct.pack('<f', n))[0])
        returnValue = "\\x"+"\\x".join(b for b in re.findall('..',returnValue.split('x')[1])[::-1])  
        return str(returnValue)

    def getCoord(self, s):
        while True:  
            line = s.readline().decode('utf-8')
            data = line.split(",")
            
            if data[0] == "$GPGLL":
                if data[1]=='':
                    lat = 0.0
                    long = 0.0
                    return lat, long

                lat = data[1]
                lat = int(lat[:2])+float(lat[2:])/60
                latDir = data[2]
                long = data[3]
                long = int(long[:3])+float(long[3:])/60
                longDir = data[4]

                if latDir == 'S':
                    lat = -lat

                if longDir == 'W':
                    long = -long
                    
                time     = data[5].split(".")[0]
                timeFrance = int(time) + 20000
                break
            
        return lat,long

    def _newFrame(self, frame):
        """
        Just received a full frame from the sniffer
        """
        self.line += frame
        #Add GPS coordinates
        lat, long = self.getCoord(self.serial)
        lat = self.float2hex(lat)
        long = self.float2hex(long)
        
        frame1 = ''.join([chr(b) for b in self.line[:27]])
        frame2 = ''.join([chr(b) for b in self.line[35:]])
        f = '\xd7\x63\x43\x42'        
        self.outfile.write(frame1+str(lat)+str(long)+frame2)
        self.counter                      += 1
        winsound.Beep(self.FREQUENCY, self.DURATION)
        print ("Frames : ", self.counter)

    

    
                

#============================ main ============================================


def main():    
    # start thread
    rxSnifferThread     = RxSnifferThread()
if __name__ == "__main__":
    main()
