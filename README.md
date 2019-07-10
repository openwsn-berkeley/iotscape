# iotscape

1. Download the FTDI D2XX drivers from https://www.ftdichip.com/Drivers/D2XX.htm

- Select the driver "1.4.8 ARMv6 hard-float (suits Raspberry Pi)" for Linux systems

2. Go to the Downloads directory and extract the driver's files

- cd Downloads
- tar -xvf lib*
- sudo cp release/build/lib* /usr/local/lib

3. Link the driver library

- cd /usr/local/lib
- sudo ln -s libftd2xx.so.1.4.8 libftd2xx.so

4. Change the permissions

- sudo chmod 0755 libftd2xx.so.1.4.8

5. Download Adapter software for linux from http://www.beamlogic.com/802-15-4-siteanalyzer 

6. Extract the files into a new folder on the Desktop named "adapter"

7. Generate files

- cd adapter/
- make

8. Install supervisor, screen and git packages

- sudo apt-get install supervisor -y
- sudo apt-get install screen -y
- sudo apt-get install git

9. Download configuration files

- cd Desktop 
- git clone https://github.com/openwsn-berkeley/iotscape.git

10. Move iotscape.sh file to adapter

- sudo cp iotscape.sh /Desktop/adapter
- cd ~/Desktop/adapter
- chmod u+x ./iotscape.sh

11. Set up supervisor

- cd ~/Desktop/iotscape
- sudo cp supervisor.conf /etc/supervisor/conf.d/
- sudo systemctl restart supervisor.service
