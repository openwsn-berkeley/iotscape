#!/bin/bash

current_time=$(date "+%Y%m%d-%H:%M:%S")
sudo rmmod ftdi_sio
sudo rmmod usbserial
sudo ./adapter -o raw_beamlogic_$current_time.txt
