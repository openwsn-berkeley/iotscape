import serial

FILENAME_OUTPUT = 'position.log'
PORT            = 'COM28'

with open(FILENAME_OUTPUT, "a") as outfile:
    while True:
        try:
            s = serial.Serial(PORT,9600)
            while True:    
                line = s.readline().decode('utf-8')
                outfile.write(line)
                
        except IOError:
            print "Could not read from {0}".format(PORT)
        
