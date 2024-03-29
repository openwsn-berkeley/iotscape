# Python
import time
import struct
import threading
import Queue
import traceback
# third-party
import winsound

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
    
    OFFSET_RSSI              = 10
    PCAP_GLOBALHEADER_LEN    = 24 # 4+2+2+4+4+4+4
    PCAP_PACKETHEADER_LEN    = 16 # 4+4+4+4
    BEAMLOGIC_HEADER_LEN     = 20 # 1+8+1+1+4+4+1
    PIPE_SNIFFER             = r'\\.\pipe\analyzer'
    
    def __init__(self, writingThread, beepingThread):

        # store params
        self.writingThread             = writingThread
        self.beepingThread             = beepingThread

        # local variables
        self.dataLock                  = threading.Lock()
        self.rxBuffer                  = []
        self.doneReceivingGlobalHeader = False
        self.doneReceivingPacketHeader = False
        self.packet                    = []
        
        # start the thread
        threading.Thread.__init__(self)
        self.name                      = 'RxSnifferThread'
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

                    # send global header
                    self.writingThread.publishFrame(self.rxBuffer)
                    self.rxBuffer                     = []

            # PCAP packet header
            elif not self.doneReceivingPacketHeader:
                if len(self.rxBuffer) == self.PCAP_PACKETHEADER_LEN:
                    self.doneReceivingPacketHeader    = True
                    self.packetHeader                 = self._parsePcapPacketHeader(self.rxBuffer)
                    assert self.packetHeader['incl_len'] == self.packetHeader['orig_len']

                    # append header to packet
                    self.packet                       = self.rxBuffer
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

    def _newFrame(self, frame):
        """
        Just received a full frame from the sniffer
        """
        self.packet += frame
        self.writingThread.publishFrame(self.packet)
        self.beepingThread.beep(frame[self.OFFSET_RSSI])

class WritingThread(threading.Thread):

    FILENAME_OUTPUT          = '{0}_packets.pcap'.format(time.strftime('%Y%m%d-%Hh%Mm%Ss'))

    def __init__(self):

        # local variables
        self.wrQueue         = Queue.Queue(maxsize=100)
        self.outfile         = open(self.FILENAME_OUTPUT,'wb')
        
        # start the thread
        threading.Thread.__init__(self)
        self.name            = 'WritingThread'
        self.start()

    def run(self):
        try:
            while True:
                # wait for first frame
                data = [self.wrQueue.get(), ]

                # get other packets (if any)
                try:
                    while True:
                        data += [self.wrQueue.get(block=False)]
                except Queue.Empty:
                    # write data
                    for f in data:
                        packet = ''.join([chr(b) for b in f])
                        self.outfile.write(packet)
                    pass
                time.sleep(5)
                
        except Exception as err:
            logCrash(self.name, err)

    #======================== public ==========================================

    def publishFrame(self, frame):

        try:
            self.wrQueue.put(frame, block=False)
        except Queue.Full:
            print "WARNING WritingThread queue full. Dropping frame."

    #======================== private =========================================


class BeepingThread(threading.Thread):

    FREQ_MIN = 440
    FREQ_MAX = 880
    MAX_RSSI =  30

    def __init__(self):

        # local variables
        self.queue           = Queue.Queue(maxsize=100)
        
        # start the thread
        threading.Thread.__init__(self)
        self.name            = 'BeepingThread'
        self.start()

    def run(self):
        try:
            while True:
                # wait for first frame
                rssi = self.queue.get()

                # compute frequency
                freq = int(self.FREQ_MIN+(float(self.FREQ_MAX-self.FREQ_MIN)*float(float(rssi)/float(self.MAX_RSSI))))
                
                # beep
                winsound.Beep(freq,50)
                
        except Exception as err:
            logCrash(self.name, err)

    #======================== public ==========================================

    def beep(self, rssi):

        try:
            self.queue.put(rssi)
        except Queue.Full:
            print "WARNING BeepingThread queue full. Skipping beep."

    #======================== private =========================================

#============================ main ============================================


def main():    
    # start thread
    writingThread            = WritingThread()
    beepingThread            = BeepingThread()
    rxSnifferThread          = RxSnifferThread(writingThread,beepingThread)
if __name__ == "__main__":
    main()
