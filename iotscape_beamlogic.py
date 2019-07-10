import struct

INFILE  = 'raw_beamlogic.txt'
OUTFILE = 'beamlogic.pcap'

def writebytes(bytes,f):
    f.write(''.join([chr(b) for b in bytes]))

with open(OUTFILE,'wb') as outfile:
    
    # write global PCAP header
    globalheader = [
        0xd4, 0xc3, 0xb2, 0xa1,   # magic_number
        0x02, 0x00,               # version_major
        0x04, 0x00,               # version_minor
        0x00, 0x00, 0x00, 0x00,   # thiszone
        0x00, 0x00, 0x00, 0x00,   # sigfigs
        0x00, 0x00, 0x04, 0x00,   # sigfigs
        0xe6, 0x00, 0x00, 0x00,   # network
    ]
    writebytes(globalheader,outfile)
    
    with open(INFILE,'r') as infile:
    
        for line in infile.readlines():
            
            # parse
            try:
                ts     = float(line.split(' - ')[0])
                bytes  = [int(b,16) for b in line.split(' - ')[1].split()]
            except ValueError:
                continue
        
            # parse
            ts_sec  = int(ts)
            ts_usec = int(ts*1000000)%1000000
            
            # write
            frame  = []
            frame += [ord(b) for b in struct.pack('<IIII',ts_sec,ts_usec,len(bytes),len(bytes))]
            frame += bytes
            writebytes(frame,outfile)

raw_input('done')
