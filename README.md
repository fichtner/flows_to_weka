Wonka Flows Exporter
====================

Export pcap files with TCP traffic to TCP Flows and output it to WEKA or CSV

Features being extracted:

* delta between packet's arrival time
* bytes transferred should it be a ratio between bytes transfered/number of packages
* ratio push flag/total flags

### HOW TO INSTALL
```
git clone https://github.com/fichtner/flows_to_weka.git
cd flows_to_weka
pip install -r requirements.txt
```

### HOW TO USE IT

`./wfe.py -i input.pcap -t csv|arff > output_file.extension`

then you can import the CSV into R or ARFF into WEKA

Author: v.pereira@packetwerk.de
License: MIT
