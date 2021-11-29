# TCP Flag Filter
This is a simple command line application that lets a user obtain information about packets filtered according to any of the TCP header flags. Built with [Python (v3.6.9)](https://www.python.org/downloads/release/python-369/), this is can useful tool for network traffic analysis, if used in tandem with other network analysis tools.

## How it Works
### Input
The application takes a network traffic file of the `.pcap` file type as input
### Output
The application provides the user with a file named `flag_data.txt` as output. It contains the following data for every packet in the traffic file containing the requested header flag:
- *Source Port* : Source port of the packet
- *Destination Port* : Destination port of the packet
- *Source IP Address* : Source IP address of the packet
- *Destination IP Address* : Destination IP address of the packet
- *Flags Present* : A space separated list of flags present on that particular packet
### Files involved
The following are the files involved in the entire application.
- **sample_capture.pcap** : Packet capture file from any network
- **flag_data.txt** : Packet information about the filtered TCP packets 

## Get it running
### Prerequisites
- Clone the repository from [here](https://github.com/Parthiv-M/tcp-flag-filter) using the following command
```
git clone https://github.com/Parthiv-M/tcp-flag-filter
```
- Have [Python](https://www.python.org/downloads/release/python-360/) installed on your system, at least version >= 3.6 
- Install the external modules required from the `requirements.txt` file with the following command
```
pip install -r requirements.txt
```
### Running the command line application
Run the command line application with the following commands
```
python3 tcp_searcher.py
```
This should get you started with analysing TCP packets based on header flag bits  

## Screenshots
### The menu presented to users
![]("https://github.com/Parthiv-M/tcp-flag-filter/blob/master/extras/image1.png")
### The menu is prompted again after the user enters a valid file name
![]("https://github.com/Parthiv-M/tcp-flag-filter/blob/master/extras/image2.png")
### A summary of the traffic file is given to the user
![]("https://github.com/Parthiv-M/tcp-flag-filter/blob/master/extras/image3.png")
### Upon entering a valid TCP flag, a file with the relevant packet details is generated
![]("https://github.com/Parthiv-M/tcp-flag-filter/blob/master/extras/image4.png")
### The file containing packet details of the filtered packets
![]("https://github.com/Parthiv-M/tcp-flag-filter/blob/master/extras/image5.png")

## Contributors
[Parthiv Menon](https://github.com/Parthiv-M) and [Dhyan Gandhi](https://github.com/Hydron13) worked on this project as part of the **Mini-Project for Computer Networking**. 