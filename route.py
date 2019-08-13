# Python
import json
import struct
import glob

gpsData = []
#gpsDataFilter = []
data = {
  "type": "FeatureCollection",
  "features": []
}
def computeLatLon(lat,lat_heading,lon,lon_heading):
    outlat          = int(lat[:2])+float(lat[2:])/60
    if lat_heading == 'S':
        outlat      = -outlat
    outlon          = int(lon[:3])+float(lon[3:])/60
    if lon_heading == 'W':
        outlon      = -outlon
    return (outlat,outlon)

# parse GPS log files
for filename in glob.glob('*.log'):
    print 'parsing {0}'.format(filename)
    with open(filename, 'r') as f:
        for line in f:
            if line.startswith('$GPRMC'):
                
                # parse
                elems          = line.split(',')
                lat            = elems[3]
                lat_heading    = elems[4]
                lon            = elems[5]
                lon_heading    = elems[6]

                # skip line if no position acquired
                if lat=='':
                    continue
                
                # location
                location       = computeLatLon(lat,lat_heading,lon,lon_heading)
                gpsData        += [location]

# for x in xrange(0,len(gpsData),5):   
    # gpsDataFilter += [[gpsData[x][1],gpsData[x][0]]]

# data = {
  # "type": "FeatureCollection",
  # "features": [
    # {
      # "type": "Feature",
      # "properties": {},
      # "geometry": {
        # "type": "LineString",
        # "coordinates": gpsDataFilter
      # }
    # }
  # ]
# }

for x in xrange(0,len(gpsData),10):   
    # geoJSON structure
    data['features'].append({
          "type": "Feature",
          "properties": { 
          "marker-symbol": "",
          "marker-color": "#000000", # RGB(HEX) red -> "#ff0000", green -> "#00ff00", blue -> "#0000ff"
          "marker-size": "small"
          },
          "geometry": {
            "type": "Point",
            "coordinates": [
              gpsData[x][1],
              gpsData[x][0]
            ]
          }
        })
                
# writing JSON object# 
with open('route.json', 'w') as f:   
    json.dump(data, f)
