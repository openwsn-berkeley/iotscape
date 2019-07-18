import serial

FILENAME_OUTPUT = 'gpsData.txt'
PORT            = 'COM28'

with open(FILENAME_OUTPUT, "a") as outfile:
    try:
        s = serial.Serial(PORT,9600)
        while True:    
            line = s.readline().decode('utf-8')
            outfile.write(line)
            
    except IOError:
        print "Could not read from serial port"
        
