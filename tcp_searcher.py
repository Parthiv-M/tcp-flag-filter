from os.path import exists
from os import system
from scapy.all import *

def search_tcp(filename):
    packet_list = []

    packet_count = 0

    a = rdpcap(filename)

    sessions = a.sessions()    

    for session in sessions:
        http_payload = ""
        for packet in sessions[session]:
            try:
                packet_count = packet_count + 1
                if packet["TCP"].dport == 80 or packet["TCP"].sport == 80 or packet["TCP"].sport == 443 or packet["TCP"].dport == 443:
                    packet_dict = {
                        "dport": "",
                        "sport" : "",
                        "d_ip": "",
                        "s_ip": "",
                        "packet_sum" : "",
                        "flags" : ""
                    }
                    packet_dict["packet_sum"] = packet.summary()
                    packet_dict["sport"] = packet["TCP"].sport
                    packet_dict["dport"] = packet["TCP"].dport
                    packet_dict["d_ip"] = packet["IP"].dst
                    packet_dict["s_ip"] = packet["IP"].src
                    F = packet["TCP"].flags
                    flag_list = ""
                    if(F & 0x01):
                        flag_list += "FIN "
                    if(F & 0x02):
                        flag_list += "SYN "
                    if(F & 0x04):
                        flag_list += "RST "
                    if(F & 0x08):
                        flag_list += "PSH "
                    if(F & 0x10):
                        flag_list += "ACK "
                    if(F & 0x20):
                        flag_list += "URG "
                    if(F & 0x20):
                        flag_list += "ECE "
                    if(F & 0x80):
                        flag_list += "CWR "
                    packet_dict["flags"] = ""
                    packet_dict["flags"] += flag_list
                    packet_list.append(packet_dict)
                    http_payload += "".join(map(chr, bytes(packet["TCP"].payload)))
            except: 
                pass       

    print("=========================================")
    print("Traffic File Summary for " + filename)
    print("=========================================")
    print("Total number of sessions captured: \033[93m" + str(len(sessions)) + "\033[0m")
    print("Total number of packets: \033[93m" + str(packet_count) + "\033[0m")
    print("Total number of TCP packets: \033[93m" + str(len(packet_list)) + "\033[0m")
    print("TCP packets as a percentage of total packets captured: \033[93m{0:.3f}%\033[0m".format((len(packet_list)/packet_count) * 100))
    return packet_list

def is_file_pcap(filename):
    extension = filename.split(".")
    if(extension[1] == "pcap"):
        return True
    else:
        return False

def get_file_name():
    f_name = str(input("Enter file name or path to the traffic file (pcap file): "))
    file_exists = exists(f_name)
    if(file_exists):
        return f_name
    return False

def get_flag_name():
    f_name = str(input("\nEnter a TCP flag to search for (among the TCP packets): "))
    if f_name in ["ACK", "SYN", "FIN", "RST", "PSH", "URG", "ECE", "CWR"]:
        return f_name
    return False

def search_tcp_flag(flag, packet_list):
    filtered_list = []
    
    for packet in packet_list:
        if flag in packet["flags"].split(" "):
            filtered_list.append(packet)
        else:
            pass
    for flag_pack in filtered_list:
        file = open("flag_data.txt", 'a')
        strings_to_write = [
            "========================================",
            "\nSource port: " + str(flag_pack["sport"]),
            "\nDestination port: " + str(flag_pack["dport"]),
            "\nSource IP Address: " + str(flag_pack["s_ip"]),
            "\nDestination IP Address: " + str(flag_pack["d_ip"]),
            "\nFlags present: " + str(flag_pack["flags"].strip()) + "\n"
        ]
        file.writelines(strings_to_write)
        file.close()
    print("\nNumber of packets with \033[95m" + flag + "\033[0m flag: " + str(len(filtered_list)))
    print("Packet data successfully saved to \033[91m\033[1m\033[4mflag_data.txt\033[0m")

def menu():
    print("\n\033[4m\033[1mTCP PACKET FLAG BASED FILTER MENU\033[0m")
    print("1. Choose a traffic file")
    print("2. Generate a new report file")
    print("3. Exit")
    choice = int(input("Enter a choice: "))
    print("\n")
    _ = system('clear')
    if choice < 1 or choice > 3:
        print("Enter a valid choice")
        return 0
    return choice

def main():

    filename = ""

    while(1):
        menu_choice = menu()
        if menu_choice != 0:
            if menu_choice == 1:
                filename = get_file_name()
                if filename == False:
                    print("Incorrect file or path name!")
                    return
                else:
                    print()
            elif menu_choice == 2:
                if(is_file_pcap(filename)):
                    pack_list = search_tcp(filename)
                else:
                    print("File type not accepted. Please give a valid pcap file.")
                    return
                flag_to_search = get_flag_name()
                if flag_to_search != False:
                    print("\nSearching for packets with \033[95m" + flag_to_search + "\033[0m flag...")
                    search_tcp_flag(flag_to_search, pack_list)
            elif menu_choice == 3:
                print("\nExiting..\n")
                break
            else:
                print("\nAn error occured\n")
                break

if __name__ == "__main__":
    main()
