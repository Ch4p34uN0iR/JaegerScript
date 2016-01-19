import subprocess, threading
import os,signal
from subprocess import Popen, PIPE

#This tool was made by Rafael Gil
#depasonico@gmail.com
#
#
#This is the main menu in this section we choose the kind of pentest to be deployed
#It is important use the new structure of Python 3
#
def main_menu ():
        menu = {} #array for the menu
        menu['1']="Internal Pentest" #list for Internal pentest 
        menu['2']="External Pentest" #list for external pentest
        menu['3']="Version"
        menu['4']="Exit" #option to break the cicle
        while True: #with this boolean we keep the menu every time
                print ('1', menu['1']) #printing the values in the array
                print ('2', menu['2']) #do not use sort the result is different
                print ('3', menu['3'])
                print ('4', menu['4'])
                selection=input("Please Select:") #new function for capturing data from keyboard
                if selection =='1': #             this function calls internal_pentest() the one for the internal part    
                        internal_pentest() 
                elif selection == '2': 
                        external_pentest()
                elif selection == '3':
                        print ("Version 1.0")
                elif selection == '4':
                        break                
                else: 
                        print ("Unknown Option Selected!") #exception for any malformed input
        # This function is in charge of deploying the internal part and menu
        #this function is in different parts and call different other functions
        #still in development adding new functions
        #
def internal_pentest ():
        menu = {} #same kind of menu that the main menu
        menu['1']="Common Services" 
        menu['2']="Extended"
        menu['3']="Collector"
        menu['4']="Exit"
        while True: 
                print ('1', menu['1'])
                print ('2', menu['2'])
                print ('3', menu['3'])
                print ('4', menu['4'])
                selection=input("Please Select:") 
                if selection =='1': 
                        common_intenal_pentest() #this function is in charge of deploying the most common pentest in the most common ports
                elif selection == '2': 
                        extended_internal_pentest() #this function is in charge of deploying no common ports scan
                elif selection == '3':
                        collector()                
                elif selection == '4':
                        break
                else: 
                        print ("Unknown Option Selected!")
                        
def external_pentest():
        menu = {} #same kind of menu that the main menu
        menu['1']="Common External Pentest" 
        menu['2']="Advance External (3l33t)"
        menu['3']="Collector"
        menu['4']="Exit"
        while True: 
                print ('1', menu['1'])
                print ('2', menu['2'])
                print ('3', menu['3'])
                print ('4', menu['4'])
                selection=input("Please Select:") 
                if selection =='1': 
                        common_external() #this function is in charge of deploying the most common pentest in the most common ports
                elif selection == '2': 
                        print ("Under Contruction 2016") #this function is in charge of deploying no common ports scan
                elif selection == '3':
                        collector()                
                elif selection == '4':
                        break
                else: 
                        print ("Unknown Option Selected!")        
#This function is one of the biggest in this script
#it contains three parts
#1.- Discovery the segment to scan, after it generates a file with all the live IPs using PE in nmap
#2.- TCP scanning for the common ports
#3.- UDP scanning for the common ports
def common_intenal_pentest ():
        import nmap  #using python nmap library
        import os #library to create directories and use other OS functions
        import datetime
        import time    
        print ('Provide the name of the company')
        company = input ("Company: ")
        print ('Provide the IP range to scan: \n IP: 192.168.1.1 \n Range: 192.168.1.1/24 \n Range: 192.168.1.1-254 \n Domain: google.com')
        IP_segment = input("IP: ") #it can get range or single ip
        host = str(IP_segment) #change the type 
        ts = time.time() #getting time        
        st = datetime.datetime.fromtimestamp(ts).strftime('_%Y_%m_%d_%H_%M') #human read
        timestamp = str(st) #changinf the type
        directory = company + timestamp #company and time of the scan
        directory = str(directory) #change the type
        f = open('/tmp/directory.txt', 'w') #create the file for directory
        f.write('/root/pentest'+directory+'/discovery') #write the string
        f.close()
        os.mkdir('/root/pentest'+directory) #create the directory
        os.mkdir('/root/pentest'+directory+'/discovery')  #create the directory 
        os.mkdir ('/root/pentest'+directory+'/discovery/logs')
        os.mkdir ('/root/pentest'+directory+'/discovery/collector')
        pentest = nmap.PortScanner() #create a type scanner form nmap library
        pentest.scan(hosts= host, arguments='-sn') #this function in the labrary calls nmap the usage is hosts, ports, arguments
        f = open('/root/pentest'+directory+'/discovery/logs/logalive', 'a')
        ts = time.time()        
        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
        timestamp = str(st)        
        f.write('nmap hosts alive started = ' + timestamp+"\n\n")
        hosts_list = [(x, pentest[x]['status']['state']) for x in pentest.all_hosts()]
        #create the list for the live IPs
        #the value x is echange for the value in the list in the library in all_hosts
        #pentes.all_hosts() is a function to list all the hosts scanned
        print ('-------------------- Live Host -----------------------------')
        for host, status in hosts_list: #loop to check the status of all the hosts
                if 'up' in status: #condintion to detect is the host is up
                        print('{0}:{1}'.format(host, status)) #print it 
                        f = open('/root/pentest'+directory+'/discovery/LiveIPs.txt','a') #create the initial txt file of all the live IP
                        f.write('{0}'.format(host) + '\n') #it only prints the host
        print ('-------------------- Live Host -----------------------------')#tag
        f = open('/root/pentest'+directory+'/discovery/logs/logalive', 'a')
        ts = time.time()        
        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
        timestamp = str(st)        
        f.write('nmap hosts alive finished = ' + timestamp+"\n\n")        
        print ("""\n\n\n***********************************************************


        Scanning for TCP ports in all the live Hosts
                    (Coffee Time)

*********************************************************\n\n\n
               """)
        pentest = nmap.PortScanner() #new type of scan
        #This area could be improved later on
        #The list of common ports 
        #Services, versions, SO, hostnames.
        pentest.scan(arguments='-sV -vv -O -Pn --top-ports 50 --open -iL /root/pentest'+directory+'/discovery/LiveIPs.txt')        
        f = open('/root/pentest'+directory+'/discovery/logs/logscanning', 'a')
        ts = time.time()        
        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
        timestamp = str(st)        
        f.write('nmap scanning services started = ' + timestamp+"\n\n")        
        for host in pentest.all_hosts(): #loop to print and store the results by host and port
                try:                        
                        print('-------------' + host +'---------------------------') #tag
                        Hostname = str(pentest[host].hostname()) #changinf the type of this value to string
                        print ('Hostname: '+Hostname) #printing 
                        f = open('/root/pentest'+directory+'/discovery/Hostnames.csv','a') #create the file with the possible hostname
                        f.write(host + ',' + Hostname + '\n')
                except KeyError as e:
                        print ("Something wrong with nmap \(No results for scripts\)")
                        pass                 
                lport = pentest[host]['tcp'].keys() #new list with all the tcp ports in each host
                for port in lport: #this section looks for each possible port in the list above 
                        status = str(pentest[host]['tcp'][port]['state']) #store the state of each port in status list
                        if 'open' in status: #condition to detect open ports 
                                print ('port : %s\tstate : %s' % (port, pentest[host]['tcp'][port]['state'])) #printing if it is open
                                host = str(host) #change the type
                                product = str(pentest[host]['tcp'][port]['product']) #this option allows to know the service
                                version = str(pentest[host]['tcp'][port]['version']) #this option allows to know the version
                                name = str(pentest[host]['tcp'][port]['name']) #this option allows to know more details for the service
                                OS = str(pentest[host]['tcp'][port]['cpe']) #if nmap can detect the OS this option will show it
                                Extra = str(pentest[host]['tcp'][port]['extrainfo']) #any extra information to fill the report
                                f = open('/root/pentest'+directory+'/discovery/OpenPorts.csv','a') #file containing all open porst by host
                                f.write(host + ',' + name + ',' + str(port) + ',' + status + ',' + product + ',' + ',' + version + ',' +'\n')
                                f = open('/root/pentest'+directory+'/discovery/DiscoverOS.csv','a') #file containing the possible OS if found
                                f.write(host + ',' + OS + ',' + Extra +'\n') 
                                #This section extracts all the possible ports
                                #and generates the files for the next stage
                                #this dection can be improved later on
                                if '21' in str(port):
                                        f = open('/root/pentest'+directory+'/discovery/FTP21.txt','a')
                                        f.write('{0}'.format(host) + '\n')  
                                if '22' in str(port):
                                        f = open('/root/pentest'+directory+'/discovery/SSH22.txt','a')
                                        f.write('{0}'.format(host) + '\n')
                                if '23' in str(port):
                                        f = open('/root/pentest'+directory+'/discovery/TELNET23.txt','a')
                                        f.write('{0}'.format(host) + '\n')   
                                if '25' in str(port):
                                        f = open('/root/pentest'+directory+'/discovery/SMTP25.txt','a')
                                        f.write('{0}'.format(host) + '\n')  
                                if '53' in str(port):
                                        f = open('/root/pentest'+directory+'/discovery/DNS53.txt','a')
                                        f.write('{0}'.format(host) + '\n')
                                if '80' in str(port):
                                        f = open('/root/pentest'+directory+'/discovery/HTTP80.txt','a')
                                        f.write('{0}'.format(host) + '\n') 
                                if '139' in str(port):
                                        f = open('/root/pentest'+directory+'/discovery/NETBIOS139.txt','a')
                                        f.write('{0}'.format(host) + '\n')  
                                if '443' in str(port):
                                        f = open('/root/pentest'+directory+'/discovery/HTTPS443.txt','a')
                                        f.write('{0}'.format(host) + '\n')
                                if '8080' in str(port):
                                        f = open('/root/pentest'+directory+'/discovery/HTTP8080.txt','a')
                                        f.write('{0}'.format(host) + '\n')   
                                if '445' in str(port):
                                        f = open('/root/pentest'+directory+'/discovery/SMB445.txt','a')
                                        f.write('{0}'.format(host) + '\n')  
                                if '513' in str(port):
                                        f = open('/root/pentest'+directory+'/discovery/RLOGIN513.txt','a')
                                        f.write('{0}'.format(host) + '\n')
                                if '514' in str(port):
                                        f = open('/root/pentest'+directory+'/discovery/RSH514.txt','a')
                                        f.write('{0}'.format(host) + '\n')
                                if '2048' in str(port):
                                        f = open('/root/pentest'+directory+'/discovery/NFS2048.txt','a')
                                        f.write('{0}'.format(host) + '\n')  
                                if '2049' in str(port):
                                        f = open('/root/pentest'+directory+'/discovery/NFS2049.txt','a')
                                        f.write('{0}'.format(host) + '\n')
                                if '111' in str(port):
                                        f = open('/root/pentest'+directory+'/discovery/NFS111.txt','a')
                                        f.write('{0}'.format(host) + '\n')
                                if '1433' in str(port):
                                        f = open('/root/pentest'+directory+'/discovery/MSSQL1433.txt','a')
                                        f.write('{0}'.format(host) + '\n')   
                                if '3306' in str(port):
                                        f = open('/root/pentest'+directory+'/discovery/MYSQL3306.txt','a')
                                        f.write('{0}'.format(host) + '\n')  
                                if '1521' in str(port):
                                        f = open('/root/pentest'+directory+'/discovery/ORACLE1521.txt','a')
                                        f.write('{0}'.format(host) + '\n')
                                if '389' in str(port):
                                        f = open('/root/pentest'+directory+'/discovery/LDAP389.txt','a')
                                        f.write('{0}'.format(host) + '\n') 
                                if '135' in str(port):
                                        f = open('/root/pentest'+directory+'/discovery/MSRPC135.txt','a')
                                        f.write('{0}'.format(host) + '\n')  
                                if '6000' in str(port):
                                        f = open('/root/pentest'+directory+'/discovery/X116000.txt','a')
                                        f.write('{0}'.format(host) + '\n')   
                                if '79' in str(port):
                                        f = open('/root/pentest'+directory+'/discovery/FINGER79.txt','a')
                                        f.write('{0}'.format(host) + '\n')  
                                if '5900' in str(port):
                                        f = open('/root/pentest'+directory+'/discovery/VNC5900.txt','a')
                                        f.write('{0}'.format(host) + '\n')
                                if '5800' in str(port):
                                        f = open('/root/pentest'+directory+'/discovery/VNC5800.txt','a')
                                        f.write('{0}'.format(host) + '\n')                                
                                if '587' in str(port):
                                        f = open('/root/pentest'+directory+'/discovery/MICRODS.txt','a')
                                        f.write('{0}'.format(host) + '\n')
                                if '512' in str(port):
                                        f = open('/root/pentest'+directory+'/discovery/EXEC512.txt','a')
                                        f.write('{0}'.format(host) + '\n')  
                                if '3268' in str(port):
                                        f = open('/root/pentest'+directory+'/discovery/GC3268.txt','a')
                                        f.write('{0}'.format(host) + '\n')
                                if '3269' in str(port):
                                        f = open('/root/pentest'+directory+'/discovery/GCLSSL3269.txt','a')
                                        f.write('{0}'.format(host) + '\n') 
                                if '3389' in str(port):
                                        f = open('/root/pentest'+directory+'/discovery/RDP3389.txt','a')
                                        f.write('{0}'.format(host) + '\n')                                        
                                if '50000' in str(port):
                                        f = open('/root/pentest'+directory+'/discovery/DB2.txt','a')
                                        f.write('{0}'.format(host) + '\n') 
        f = open('/root/pentest'+directory+'/discovery/logs/logalive', 'a')
        ts = time.time()        
        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
        timestamp = str(st)        
        f.write('nmap scanning services finished = ' + timestamp+"\n\n")        
        #new type of scane for UDP
        #for UDP the arguments are different and the results
        pentest = nmap.PortScanner()
        pentest.scan(arguments='-d --max-retries 6 -sU -T5 -n -P0 --top-ports 50 -iL /root/pentest'+directory+'/discovery/LiveIPs.txt')        
        ts = time.time()        
        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
        timestamp = str(st)        
        f.write('nmap scanning services UDP started = ' + timestamp+"\n\n")        
        print ('-------------Now UDP scan sit and pray-----------------') #tag
        for host in pentest.all_hosts(): #loop to check all the hosts scanned
                print('-------------' + host +'---------------------------') #tag
                lport = pentest[host].all_udp() #list containing all udp ports scanned for each host
                for port in lport: #checking port by poart
                        status = str(pentest[host]['udp'][port]['state']) #first obtaining the state of the service
                        if 'open' in status or 'open|filtered' in status: #conditional if to detect if it is open or filtered (for UDP both can be useful)
                                print ('port : %s\tstate : %s' % (port, pentest[host]['udp'][port]['state'])) #printing
                                host = str(host)# change type
                                #The same technique as in TCP
                                #Set variables for different information
                                product = str(pentest[host]['udp'][port]['product'])
                                version = str(pentest[host]['udp'][port]['version'])
                                name = str(pentest[host]['udp'][port]['name'])
                                OS = str(pentest[host]['udp'][port]['cpe'])
                                Extra = str(pentest[host]['udp'][port]['extrainfo'])
                                #Write the information in OpenPorts file
                                #But this new conditional is going to print only open ports in the file
                                if 'open' in status and not 'open|filtered' in status:
                                        f = open('/root/pentest'+directory+'/discovery/OpenPorts.csv','a')
                                        #Creates the CSV file with the information we need
                                        f.write(host + ',' + name + ',' + str(port) + ',' + status + ',' + product + ',' + ',' + version + ',' +'\n')                             
                                #This section is the same as in TCP but for UDP ports
                                #Each file is for each service (here we store open and open|filter)
                                if '69' in str(port):
                                        f = open('/root/pentest'+directory+'/discovery/TFTP69.txt','a')
                                        f.write('{0}'.format(host) + '\n')
                                if '53' in str(port):
                                        f = open('/root/pentest'+directory+'/discovery/DNS53.txt','a')
                                        f.write('{0}'.format(host) + '\n')                                 
                                if '161' in str(port):
                                        f = open('/root/pentest'+directory+'/discovery/SNMP161.txt','a')
                                        f.write('{0}'.format(host) + '\n')
                                if '123' in str(port):
                                        f = open('/root/pentest'+directory+'/discovery/NTP123.txt','a')
                                        f.write('{0}'.format(host) + '\n') 
                                if '111' in str(port):
                                        f = open('/root/pentest'+directory+'/discovery/RPCBIND111.txt','a')
                                        f.write('{0}'.format(host) + '\n') 
                                if '500' in str(port):
                                        f = open('/root/pentest'+directory+'/discovery/IKE500.txt','a')
                                        f.write('{0}'.format(host) + '\n') 
                                if '2049' in str(port):
                                        f = open('/root/pentest'+directory+'/discovery/NFS2049.txt','a')
                                        f.write('{0}'.format(host) + '\n') 
                                if '2048' in str(port):
                                        f = open('/root/pentest'+directory+'/discovery/NFS2048.txt','a')
                                        f.write('{0}'.format(host) + '\n') 
                                if '1434' in str(port):
                                        f = open('/root/pentest'+directory+'/discovery/MSSQLUDP1434.txt','a')
                                        f.write('{0}'.format(host) + '\n') 
                                if '137' in str(port):
                                        f = open('/root/pentest'+directory+'/discovery/NETBIOSU137.txt','a')
                                        f.write('{0}'.format(host) + '\n')   
                                if '138' in str(port):
                                        f = open('/root/pentest'+directory+'/discovery/NETBIOS138.txt','a')
                                        f.write('{0}'.format(host) + '\n')
        ts = time.time()        
        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
        timestamp = str(st)        
        f.write('nmap scanning services UDP finished = ' + timestamp+"\n\n")        



def common_external():
        import nmap  #using python nmap library
        import os #library to create directories and use other OS functions
        import datetime
        import time    
        print ('Provide the name of the company')
        company = input ("Company: ")
        print ('Provide the list of IP range to scan: \n IP: 192.168.1.1 \n Range: 192.168.1.1/24 \n Range: 192.168.1.1-254 \n Domain: google.com')
        IP_segment = input("File: ") #it can get range or single ip
        hosts = str(IP_segment) #change the type 
        File = os.path.isfile(hosts)
        if File == True:
                ts = time.time() #getting time        
                st = datetime.datetime.fromtimestamp(ts).strftime('_%Y_%m_%d_%H_%M') #human read
                timestamp = str(st) #changinf the type
                directory = company + timestamp #company and time of the scan
                directory = str(directory) #change the type
                f = open('/tmp/directory.txt', 'w') #create the file for directory
                f.write('/root/pentest'+directory+'/discovery') #write the string
                f.close()
                os.mkdir('/root/pentest'+directory) #create the directory
                os.mkdir('/root/pentest'+directory+'/discovery')  #create the directory 
                os.mkdir ('/root/pentest'+directory+'/discovery/logs')
                os.mkdir ('/root/pentest'+directory+'/discovery/collector')       
                print ("""\n\n\n***********************************************************
        
        
                Scanning for TCP ports in all the Hosts
                            (Coffee Time)
        
        *********************************************************\n\n\n
                       """)
                pentest = nmap.PortScanner() #new type of scan
                #This area could be improved later on
                #The list of common ports 
                #Services, versions, SO, hostnames.
                pentest.scan(arguments='-sV -O -Pn --top-ports 50 --open -iL '+hosts)        
                f = open('/root/pentest'+directory+'/discovery/logs/logscanning', 'a')
                ts = time.time()        
                st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                timestamp = str(st)        
                f.write('nmap scanning services started = ' + timestamp+"\n\n")        
                for host in pentest.all_hosts(): #loop to print and store the results by host and port
                        print('-------------' + host +'---------------------------') #tag
                        Hostname = str(pentest[host].hostname()) #changinf the type of this value to string
                        print ('Hostname: '+Hostname) #printing 
                        f = open('/root/pentest'+directory+'/discovery/Hostnames.csv','a') #create the file with the possible hostname
                        f.write(host + ',' + Hostname + '\n')                
                        lport = pentest[host]['tcp'].keys() #new list with all the tcp ports in each host
                        for port in lport: #this section looks for each possible port in the list above 
                                status = str(pentest[host]['tcp'][port]['state']) #store the state of each port in status list
                                if 'open' in status: #condition to detect open ports 
                                        print ('port : %s\tstate : %s' % (port, pentest[host]['tcp'][port]['state'])) #printing if it is open
                                        host = str(host) #change the type
                                        product = str(pentest[host]['tcp'][port]['product']) #this option allows to know the service
                                        version = str(pentest[host]['tcp'][port]['version']) #this option allows to know the version
                                        name = str(pentest[host]['tcp'][port]['name']) #this option allows to know more details for the service
                                        OS = str(pentest[host]['tcp'][port]['cpe']) #if nmap can detect the OS this option will show it
                                        Extra = str(pentest[host]['tcp'][port]['extrainfo']) #any extra information to fill the report
                                        f = open('/root/pentest'+directory+'/discovery/OpenPorts.csv','a') #file containing all open porst by host
                                        f.write(host + ',' + name + ',' + str(port) + ',' + status + ',' + product + ',' + ',' + version + ',' +'\n')
                                        f = open('/root/pentest'+directory+'/discovery/DiscoverOS.csv','a') #file containing the possible OS if found
                                        f.write(host + ',' + OS + ',' + Extra +'\n') 
                                        #This section extracts all the possible ports
                                        #and generates the files for the next stage
                                        #this dection can be improved later on
                                        if '21' in str(port):
                                                f = open('/root/pentest'+directory+'/discovery/FTP21.txt','a')
                                                f.write('{0}'.format(host) + '\n')  
                                        if '22' in str(port):
                                                f = open('/root/pentest'+directory+'/discovery/SSH22.txt','a')
                                                f.write('{0}'.format(host) + '\n')
                                        if '23' in str(port):
                                                f = open('/root/pentest'+directory+'/discovery/TELNET23.txt','a')
                                                f.write('{0}'.format(host) + '\n')   
                                        if '25' in str(port):
                                                f = open('/root/pentest'+directory+'/discovery/SMTP25.txt','a')
                                                f.write('{0}'.format(host) + '\n')  
                                        if '53' in str(port):
                                                f = open('/root/pentest'+directory+'/discovery/DNS53.txt','a')
                                                f.write('{0}'.format(host) + '\n')
                                        if '80' in str(port):
                                                f = open('/root/pentest'+directory+'/discovery/HTTP80.txt','a')
                                                f.write('{0}'.format(host) + '\n') 
                                        if '139' in str(port):
                                                f = open('/root/pentest'+directory+'/discovery/NETBIOS139.txt','a')
                                                f.write('{0}'.format(host) + '\n')  
                                        if '443' in str(port):
                                                f = open('/root/pentest'+directory+'/discovery/HTTPS443.txt','a')
                                                f.write('{0}'.format(host) + '\n')
                                        if '8080' in str(port):
                                                f = open('/root/pentest'+directory+'/discovery/HTTP8080.txt','a')
                                                f.write('{0}'.format(host) + '\n')   
                                        if '445' in str(port):
                                                f = open('/root/pentest'+directory+'/discovery/SMB445.txt','a')
                                                f.write('{0}'.format(host) + '\n')  
                                        if '513' in str(port):
                                                f = open('/root/pentest'+directory+'/discovery/RLOGIN513.txt','a')
                                                f.write('{0}'.format(host) + '\n')
                                        if '514' in str(port):
                                                f = open('/root/pentest'+directory+'/discovery/RSH514.txt','a')
                                                f.write('{0}'.format(host) + '\n')
                                        if '2048' in str(port):
                                                f = open('/root/pentest'+directory+'/discovery/NFS2048.txt','a')
                                                f.write('{0}'.format(host) + '\n')  
                                        if '2049' in str(port):
                                                f = open('/root/pentest'+directory+'/discovery/NFS2049.txt','a')
                                                f.write('{0}'.format(host) + '\n')
                                        if '1433' in str(port):
                                                f = open('/root/pentest'+directory+'/discovery/MSSQL1433.txt','a')
                                                f.write('{0}'.format(host) + '\n')   
                                        if '3306' in str(port):
                                                f = open('/root/pentest'+directory+'/discovery/MYSQL3306.txt','a')
                                                f.write('{0}'.format(host) + '\n')  
                                        if '1521' in str(port):
                                                f = open('/root/pentest'+directory+'/discovery/ORACLE1521.txt','a')
                                                f.write('{0}'.format(host) + '\n')
                                        if '389' in str(port):
                                                f = open('/root/pentest'+directory+'/discovery/LDAP389.txt','a')
                                                f.write('{0}'.format(host) + '\n') 
                                        if '135' in str(port):
                                                f = open('/root/pentest'+directory+'/discovery/MSRPC135.txt','a')
                                                f.write('{0}'.format(host) + '\n')  
                                        if '111' in str(port):
                                                f = open('/root/pentest'+directory+'/discovery/RPCBIND111.txt','a')
                                                f.write('{0}'.format(host) + '\n')
                                        if '6000' in str(port):
                                                f = open('/root/pentest'+directory+'/discovery/X116000.txt','a')
                                                f.write('{0}'.format(host) + '\n')   
                                        if '79' in str(port):
                                                f = open('/root/pentest'+directory+'/discovery/FINGER79.txt','a')
                                                f.write('{0}'.format(host) + '\n')  
                                        if '5900' in str(port):
                                                f = open('/root/pentest'+directory+'/discovery/VNC5900.txt','a')
                                                f.write('{0}'.format(host) + '\n')
                                        if '5800' in str(port):
                                                f = open('/root/pentest'+directory+'/discovery/VNC5800.txt','a')
                                                f.write('{0}'.format(host) + '\n')                                
                                        if '587' in str(port):
                                                f = open('/root/pentest'+directory+'/discovery/MICRODS.txt','a')
                                                f.write('{0}'.format(host) + '\n')
                                        if '512' in str(port):
                                                f = open('/root/pentest'+directory+'/discovery/EXEC512.txt','a')
                                                f.write('{0}'.format(host) + '\n')  
                                        if '3268' in str(port):
                                                f = open('/root/pentest'+directory+'/discovery/GC3268.txt','a')
                                                f.write('{0}'.format(host) + '\n')
                                        if '3269' in str(port):
                                                f = open('/root/pentest'+directory+'/discovery/GCLSSL3269.txt','a')
                                                f.write('{0}'.format(host) + '\n')
                                        if '3389' in str(port):
                                                f = open('/root/pentest'+directory+'/discovery/RDP3389.txt','a')
                                                f.write('{0}'.format(host) + '\n')                                                  
                                        if '50000' in str(port):
                                                f = open('/root/pentest'+directory+'/discovery/DB2.txt','a')
                                                f.write('{0}'.format(host) + '\n') 
                f = open('/root/pentest'+directory+'/discovery/logs/logalive', 'a')
                ts = time.time()        
                st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                timestamp = str(st)        
                f.write('nmap scanning services finished = ' + timestamp+"\n\n")        
                #new type of scane for UDP
                #for UDP the arguments are different and the results
                pentest = nmap.PortScanner()
                pentest.scan(arguments='-d --max-retries 6 -sU -T5 -n -P0 --top-ports 50 -iL '+hosts)        
                ts = time.time()        
                st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                timestamp = str(st)        
                f.write('nmap scanning services UDP started = ' + timestamp+"\n\n")        
                print ('-------------Now UDP scan sit and pray-----------------') #tag
                for host in pentest.all_hosts(): #loop to check all the hosts scanned
                        print('-------------' + host +'---------------------------') #tag
                        lport = pentest[host].all_udp() #list containing all udp ports scanned for each host
                        for port in lport: #checking port by poart
                                status = str(pentest[host]['udp'][port]['state']) #first obtaining the state of the service
                                if 'open' in status or 'open|filtered' in status: #conditional if to detect if it is open or filtered (for UDP both can be useful)
                                        print ('port : %s\tstate : %s' % (port, pentest[host]['udp'][port]['state'])) #printing
                                        host = str(host)# change type
                                        #The same technique as in TCP
                                        #Set variables for different information
                                        product = str(pentest[host]['udp'][port]['product'])
                                        version = str(pentest[host]['udp'][port]['version'])
                                        name = str(pentest[host]['udp'][port]['name'])
                                        OS = str(pentest[host]['udp'][port]['cpe'])
                                        Extra = str(pentest[host]['udp'][port]['extrainfo'])
                                        #Write the information in OpenPorts file
                                        #This will be addedd to the TCP information
                                        if 'open' in status and not 'open|filtered' in status:
                                                f = open('/root/pentest'+directory+'/discovery/OpenPorts.csv','a')
                                                #Creates the CSV file with the information we need
                                                f.write(host + ',' + name + ',' + str(port) + ',' + status + ',' + product + ',' + ',' + version + ',' +'\n')                              
                                        #This section is the same as in TCP but for UDP ports
                                        #Each file is for each service (here we store open and open|filter)
                                        if '69' in str(port):
                                                f = open('/root/pentest'+directory+'/discovery/TFTP69.txt','a')
                                                f.write('{0}'.format(host) + '\n')
                                        if '53' in str(port):
                                                f = open('/root/pentest'+directory+'/discovery/DNS53.txt','a')
                                                f.write('{0}'.format(host) + '\n')                                 
                                        if '161' in str(port):
                                                f = open('/root/pentest'+directory+'/discovery/SNMP161.txt','a')
                                                f.write('{0}'.format(host) + '\n')
                                        if '123' in str(port):
                                                f = open('/root/pentest'+directory+'/discovery/NTP123.txt','a')
                                                f.write('{0}'.format(host) + '\n') 
                                        if '111' in str(port):
                                                f = open('/root/pentest'+directory+'/discovery/RPCBIND111.txt','a')
                                                f.write('{0}'.format(host) + '\n') 
                                        if '500' in str(port):
                                                f = open('/root/pentest'+directory+'/discovery/IKE500.txt','a')
                                                f.write('{0}'.format(host) + '\n')                                                
                                        if '2049' in str(port):
                                                f = open('/root/pentest'+directory+'/discovery/NFS2049.txt','a')
                                                f.write('{0}'.format(host) + '\n') 
                                        if '2048' in str(port):
                                                f = open('/root/pentest'+directory+'/discovery/NFS2048.txt','a')
                                                f.write('{0}'.format(host) + '\n') 
                                        if '1434' in str(port):
                                                f = open('/root/pentest'+directory+'/discovery/MSSQLUDP1434.txt','a')
                                                f.write('{0}'.format(host) + '\n') 
                                        if '137' in str(port):
                                                f = open('/root/pentest'+directory+'/discovery/NETBIOSU137.txt','a')
                                                f.write('{0}'.format(host) + '\n')   
                                        if '138' in str(port):
                                                f = open('/root/pentest'+directory+'/discovery/NETBIOS138.txt','a')
                                                f.write('{0}'.format(host) + '\n')
                ts = time.time()        
                st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                timestamp = str(st)        
                f.write('nmap scanning services UDP finished = ' + timestamp+"\n\n")
        if File == False:
                print("*******\n\nThe file does not exist or the path is wrong! \n\n********")

#This function look for no common ports in the network
#The base of this function is TCP and UDP like common but this scan looks for higher ports        
def extended_internal_pentest ():
        import datetime
        import time     
        print ('This part of the script needs common pentest before execution')
        print ('And the file LiveIPs.txt in /root/pentest/discovery (default)')
        import nmap  #using python nmap library    
        print ("""\n\n\n***********************************************************


        Scanning for No-common TCP ports in all the live Hosts
         (Malware could be found here, brace yourself!)
         Alert: This scan takes so much time to complete

***********************************************************************\n\n\n
               """)
        pentest = nmap.PortScanner() #new type of scan
        #This area could be improved later on
        #The list of common ports 
        #Services, versions, SO, hostnames.
        f = open('/tmp/directory.txt', 'r')
        directory = f.read()
        directory = str(directory)        
        pentest.scan(arguments='-sV -Pn -sC -p 1025-65535 -T4 --script auth-spoof,dns-zeustracker,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,http-google-malware,http-malware-host,irc-unrealircd-backdoor,smtp-strangeport,irc-botnet-channels,qconn-exec -iL '+directory+'/LiveIPs.txt')        
        f = open(directory+'/logs/logscanning', 'a')
        import datetime
        import time
        ts = time.time()        
        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
        timestamp = str(st)        
        f.write('nmap scanning extended services started = ' + timestamp +"\n\n")  
        try:
                for host in pentest.all_hosts(): #loop to print and store the results by host and port
                        print('-------------' + host +'---------------------------') #tag
                        lport = pentest[host]['tcp'].keys() #new list with all the tcp ports in each host
                        for port in lport: #this section looks for each possible port in the list above 
                                status = str(pentest[host]['tcp'][port]['state']) #store the state of each port in status list
                                if 'open' in status: #condition to detect open ports 
                                        print ('port : %s\tstate : %s' % (port, pentest[host]['tcp'][port]['state'])) #printing if it is open
                                        host = str(host) #change the type
                                        product = str(pentest[host]['tcp'][port]['product']) #this option allows to know the service
                                        version = str(pentest[host]['tcp'][port]['version']) #this option allows to know the version
                                        name = str(pentest[host]['tcp'][port]['name']) #this option allows to know more details for the service
                                        script = str(pentest[host]['tcp'][port]['script']) #any extra information to fill the report
                                        f = open(directory+'/OpenPortsNoCommon.csv','a') #file containing all open porst by host 
                                        f.write(host + ',' + name + ',' + str(port) + ',' + status + ',' + product + ',' + version + ',' + script +'\n')
        except KeyError as e:
                print ("Something wrong with nmap (No results for scripts)")
                pass                                
        print ("""\n\n\n\nThe process has finished please refer to 
        /root/pentest/discovery/OpenPortsNoCommon.csv
....................................\n\n\n\n
""")
        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
        timestamp = str(st)        
        f.write('nmap scanning extended services finished = ' + timestamp +"\n\n")        


def collector():
        print ("\n\n###############################################################\n\nWelcome to collector here is where you can select indivually or all at once\n\n###############################################################\n\n")
        menu = {} #same kind of menu that the main menu
        menu['1']="ALL" 
        menu['2']="HTTP"
        menu['3']="SSL"
        menu['4']="DNS"
        menu['5']="SNMP"
        menu['6']="SMB"
        menu['7']="SMTP"
        menu['8']="RDP"
        menu['9']="LDAP"
        menu['10']="VNC"
        menu['11']="CISCO"
        menu['12']="ORACLE"
        menu['13']="MSSQL"
        menu['14']="IKE"
        menu['15']="FTP"
        menu['16']="SSH"
        menu['17']="Exit"        
        while True: 
                print ('1', menu['1'])
                print ('2', menu['2'])
                print ('3', menu['3'])
                print ('4', menu['4'])
                print ('5', menu['5'])
                print ('6', menu['6'])
                print ('7', menu['7'])
                print ('8', menu['8'])
                print ('9', menu['9']) 
                print ('10', menu['10'])
                print ('11', menu['11'], '***Cisco Collector is only for Internal Pentest***')
                print ('12', menu['12'])
                print ('13', menu['13'])
                print ('14', menu['14'])
                print ('15', menu['15'])
                print ('16', menu['16'])
                print ('17', menu['17'])
                selection=input("Please Select:")
                if selection =='1': 
                        Check_All()
                elif selection == '2': 
                        Check_HTTP()
                elif selection == '3':
                        Check_SSL()
                elif selection == '4':
                        Check_DNS()               
                elif selection == '5':
                        Check_SNMP() 
                elif selection == '6':
                        Check_SMB() 
                elif selection == '7':
                        Check_SMTP()  
                elif selection == '8':
                        Check_RDP() 
                elif selection == '9':
                        Check_LDAP() 
                elif selection == '10':
                        Check_VNC() 
                elif selection == '11':
                        Check_Cisco()  
                elif selection == '12':
                        Check_Oracle()  
                elif selection == '13':
                        Check_MSSQL()   
                elif selection == '14':
                        Check_IKE()                            
                elif selection == '15':
                        Check_FTP()                       
                elif selection == '16':
                        Check_SSH()
                elif selection == '17':
                        break
     


def Check_HTTP():
        print ("""\n\n\nThis script needs the following tools to work:
                        bannergrab 
                        Nikto
                        Hoppy
                        nmap scripts for HTTP
        All of them should be in the system path\n\n\n""")
        import os.path
        import datetime
        import time  
        #Importing libraries to control directories and time for logs
        f = open('/tmp/directory.txt', 'r')
        #Extracting the path used before ToDo: Improve this using memory 
        directory = f.read()
        #Read the whole file (possible vulnerability)
        directory = str(directory)
        print("*************Looking for files in discovery folder**************")
        time.sleep(5)
        #Checking that the files exist 
        HttpFile = os.path.isfile(directory+"/HTTP80.txt")
        HttpFile2 = os.path.isfile(directory+"/HTTP8080.txt")
        if HttpFile != False:
                #Check for the directory and creates it
                if not os.path.exists(directory+"/collector/http"):
                        os.mkdir(directory+"/collector/http")
                else:
                        f1 = open(directory+'/logs/logHTTP', 'a')
                        import datetime
                        import time
                        time.sleep(1)
                        ts = time.time()                
                        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                        timestamp = str(st)        
                        f1.write('HTTP Collector Started = ' + timestamp +"\n\n")                     
                        f2 = open(directory+"/HTTP80.txt", "r")
                        print ("Executing bannergrab on 80 and 8080")
                        f1 = open(directory+'/logs/logHTTP', 'a')
                        ts = time.time()
                        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                        timestamp = str(st)        
                        f1.write('Bannergrab Collector Started = ' + timestamp +"\n\n")                
                        for line in f2:
                                try:
                                        line = line.rstrip('\n')
                                        from subprocess import Popen, PIPE
                                        f = open(directory+'/collector/http/HTTPCollector.txt','a') #file containing all open porst by host 
                                        f.write("\nBannergrab Version 3.5\n")
                                        cmd = "bannergrab --no-hex " + line +" 80"+" >> "+directory+"/collector/http/HTTPCollector.txt"
                                        print (cmd)
                                        p = Popen(cmd , shell=True, stdout=PIPE, stderr=PIPE)
                                        out, err = p.communicate()                   
                                        f.write("\n\n\n#########################################################\n")
                                except:
                                        pass
        if HttpFile2 != False:
                if not os.path.exists(directory+"/collector/http"):
                        os.mkdir(directory+"/collector/http")
                else:                
                        f1 = open(directory+'/logs/logHTTP', 'a')
                        ts = time.time()
                        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                        timestamp = str(st)        
                        f1.write('Bannergrab Collector Started port 8080 = ' + timestamp +"\n\n")                
                        f2 = open(directory+"/HTTP8080.txt", "r")
                        for line in f2:
                                try:
                                        line = line.rstrip('\n')
                                        from subprocess import Popen, PIPE
                                        f = open(directory+'/collector/http/HTTPCollector.txt','a') #file containing all open porst by host 
                                        f.write("\nBannergrab Version 3.5\n")
                                        cmd = "bannergrab --no-hex " + line +" 8080"+" >> "+directory+"/collector/http/HTTPCollector.txt"
                                        print (cmd)
                                        p = Popen(cmd , shell=True, stdout=PIPE, stderr=PIPE)
                                        out, err = p.communicate()                   
                                        f.write("\n\n\n#########################################################\n")
                                except:
                                        pass
                        f1 = open(directory+'/logs/logHTTP', 'a')
                        ts = time.time()
                        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                        timestamp = str(st)        
                        f1.write('Bannergrab Collector Finished = ' + timestamp +"\n\n")
        if HttpFile != False:
                if not os.path.exists(directory+"/collector/http"):
                        os.mkdir(directory+"/collector/http")
                else:                
                        print ("""Executing Nikto on 80 and 8080 """)
                        f1 = open(directory+'/logs/logHTTP', 'a')
                        ts = time.time()
                        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                        timestamp = str(st)        
                        f1.write('Nikto Collector Started Port 80 = ' + timestamp +"\n\n")                
                        f2 = open(directory+"/HTTP80.txt", "r")
                        for line in f2:
                                line = line.rstrip('\n')
                                from subprocess import Popen, PIPE
                                cmd = "nikto -host " + "http://"+line+" >> "+directory+"/collector/http/HTTPCollector.txt"
                                print (cmd)
                                command = Command(cmd)
                                command.run(timeout=600)
                                f = open(directory+'/collector/http/HTTPCollector.txt','a') #file containing all open porst by host 
                                f.write("\n#########################################################\n")
                        f1 = open(directory+'/logs/logHTTP', 'a')
                        ts = time.time()
                        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                        timestamp = str(st)  
                        f1.write('Nikto Collector Finished Port 80 = ' + timestamp +"\n\n")
                        f1.write('Nikto Collector Started Port 8080 = ' + timestamp +"\n\n")
        if HttpFile2 != False:
                if not os.path.exists(directory+"/collector/http"):
                        os.mkdir(directory+"/collector/http")
                else:                
                        f2 = open(directory+"/HTTP8080.txt", "r")
                        for line in f2:
                                line = line.rstrip('\n')
                                from subprocess import Popen, PIPE                        
                                cmd = "nikto -host " + "http://"+line+":8080"+" >> "+directory+"/collector/http/HTTPCollector.txt"
                                print (cmd)
                                command = Command(cmd)
                                command.run(timeout=600)                        
                                f2 = open(directory+'/collector/http/HTTPCollector.txt','a') #file containing all open porst by host 
                                f2.write("\n#########################################################\n")
                                f2.write("\n\n"+ cmd + "\n"+ HttpoutTxt +"\n\n\n")
                        f1 = open(directory+'/logs/logHTTP', 'a')
                        ts = time.time()
                        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                        timestamp = str(st)  
                        f1.write('Nikto Collector Finished Port 8080 = ' + timestamp +"\n\n")
                        f1.write('Hoppy Collector Started Port 80 = ' + timestamp +"\n\n")
        if HttpFile != False:
                if not os.path.exists(directory+"/collector/http"):
                        os.mkdir(directory+"/collector/http")
                else:                
                        print ("""Executing Hoppy on 80 and 8080 """)
                        f1 = open(directory+"/HTTP80.txt", "r")
                        for line in f1:
                                line = line.rstrip('\n')
                                from subprocess import Popen, PIPE
                                f2 = open(directory+'/collector/http/HTTPCollector.txt','a') #file containing all open porst by host 
                                f2.write("\n#########################################################\n")                        
                                cmd = "hoppy -h " + "http://"+line+" >> "+directory+"/collector/http/HTTPCollector.txt"
                                #cmd = "echo hi"
                                print (cmd)
                                command = Command(cmd)
                                command.run(timeout=600)
                        f1 = open(directory+'/logs/logHTTP', 'a')
                        ts = time.time()
                        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                        timestamp = str(st)  
                        f1.write('Hoppy Collector Finished Port 80 = ' + timestamp +"\n\n")
                        f1.write('Hoppy Collector Started Port 8080 = ' + timestamp +"\n\n")
        if HttpFile2 != False:
                if not os.path.exists(directory+"/collector/http"):
                        os.mkdir(directory+"/collector/http")
                else:                
                        f1 = open(directory+"/HTTP8080.txt", "r")
                        for line in f1:
                                line = line.rstrip('\n')
                                from subprocess import Popen, PIPE
                                f2 = open(directory+'/collector/http/HTTPCollector.txt','a') #file containing all open porst by host 
                                f2.write("\n#########################################################\n") 
                                cmd = "hoppy -h " + "http://"+line+":8080"+" >> "+directory+"/collector/http/HTTPCollector.txt"
                                print (cmd)
                                command = Command(cmd)
                                command.run(timeout=600)
                        f1 = open(directory+'/logs/logHTTP', 'a')
                        ts = time.time()
                        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                        timestamp = str(st)  
                        f1.write('Hoppy Collector Finished Port 8080 = ' + timestamp +"\n\n")    
                        f1.write('Nmap Collector Started Port 80 = ' + timestamp +"\n\n")
        if HttpFile != False:
                if not os.path.exists(directory+"/collector/http"):
                        os.mkdir(directory+"/collector/http")
                else:                
                        f = open(directory+'/collector/http/HTTPCollector.txt','a') #file containing all open porst by host 
                        f.write("\n#########################################################\n")                
                        print ("***********Executing all nmap scripts in HTTP ports 80 and 8080********")
                        import nmap
                        pentest = nmap.PortScanner() #new type of scan                
                        pentest.scan(arguments='-sV -sC -Pn -p 80 -T5 --script http-adobe-coldfusion-apsa1301,http-affiliate-id,http-auth-finder,http-axis2-dir-traversal,http-cisco-anyconnect,http-config-backup,http-date,http-default-accounts,http-dlink-backdoor,http-drupal-enum-users,http-exif-spider,http-frontpage-login,http-headers,http-huawei-hg5xx-vuln,http-iis-short-name-brute,http-iis-webdav-vuln,http-majordomo2-dir-traversal,http-malware-host,http-method-tamper,http-methods,http-mobileversion-checker,http-php-version,http-phpmyadmin-dir-traversal,http-qnap-nas-info,http-referer-checker,http-robtex-reverse-ip,http-robtex-shared-ns,http-slowloris-check,http-tplink-dir-traversal,http-useragent-tester,http-userdir-enum,http-vuln-cve2006-3392,http-vuln-cve2009-3960,http-vuln-cve2010-0738,http-vuln-cve2010-2861,http-vuln-cve2011-3368,http-vuln-cve2012-1823,http-vuln-cve2013-0156,http-vuln-cve2013-7091,http-vuln-cve2014-2127,http-vuln-wnr1000-creds --script=http-apache-negotiation --script-args http-apache-negotiation.root=/root/ --script http-auth --script-args http-auth.path=/login --script http-awstatstotals-exec.nse --script-args \'http-awstatstotals-exec.cmd=\"uname -a\", http-awstatstotals-exec.uri=/awstats/index.php\' --script http-barracuda-dir-traversal --script-args http-max-cache-size=5000000 --script http-coldfusion-subzero --script-args basepath=/cf/ --script=http-drupal-modules --script-args http-drupal-modules.root="/path/",http-drupal-modules.number=1000 --script http-litespeed-sourcecode-download --script-args http-litespeed-sourcecode-download.uri=/phpinfo.php --script http-ntlm-info --script-args http-ntlm-info.root=/root/ --script http-vuln-cve2011-3192.nse --script-args http-vuln-cve2011-3192.hostname=nmap.scanme.org -iL '+directory+'/HTTP80.txt')        
                        try:
                                for host in pentest.all_hosts(): #loop to print and store the results by host and port
                                        print('-------------' + host +'---------------------------') #tag
                                        lport = pentest[host]['tcp'].keys() #new list with all the tcp ports in each host
                                        for port in lport: #this section looks for each possible port in the list above 
                                                status = str(pentest[host]['tcp'][port]['state']) #store the state of each port in status list
                                                if 'open' in status: #condition to detect open ports 
                                                        print ('checking on '+ host + ' Port 80') #printing if it is open
                                                        host = str(host) #change the type
                                                        product = str(pentest[host]['tcp'][port]['product']) #this option allows to know the service
                                                        version = str(pentest[host]['tcp'][port]['version']) #this option allows to know the version
                                                        name = str(pentest[host]['tcp'][port]['name']) #this option allows to know more details for the service
                                                        script = str(pentest[host]['tcp'][port]['script']) #any extra information to fill the report
                                                        f = open(directory+'/collector/http/HTTPCollector.txt','a') #file containing all open porst by host 
                                                        list_scripts = script.split(", \'")
                                                        f.write("\n#########################################################\n")
                                                        for line in list_scripts:
                                                                f.write(host + ' ' + str(port) + ' ' + product + ' ' + version + '\n\n\n' + line +'\n\n\n\n') 
                        except KeyError as e:
                                print ("Something wrong with nmap \(No results for scripts\)")
                                pass
                        f1 = open(directory+'/logs/logHTTP', 'a')
                        ts = time.time()
                        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                        timestamp = str(st)  
                        f1.write('Nmap Collector Finished Port 80 = ' + timestamp +"\n\n")  
                        f1.write('Nmap Collector Starteded Port 8080 = ' + timestamp +"\n\n")
        if HttpFile2 != False:
                if not os.path.exists(directory+"/collector/http"):
                        os.mkdir(directory+"/collector/http")
                else:                
                        pentest.scan(arguments='-sV -Pn -p 8080 -T4 --script http-adobe-coldfusion-apsa1301,http-affiliate-id,http-auth-finder,http-axis2-dir-traversal,http-cisco-anyconnect,http-config-backup,http-date,http-default-accounts,http-dlink-backdoor,http-drupal-enum-users,http-exif-spider,http-frontpage-login,http-headers,http-huawei-hg5xx-vuln,http-iis-short-name-brute,http-iis-webdav-vuln,http-majordomo2-dir-traversal,http-malware-host,http-method-tamper,http-methods,http-mobileversion-checker,http-php-version,http-phpmyadmin-dir-traversal,http-qnap-nas-info,http-referer-checker,http-robtex-reverse-ip,http-robtex-shared-ns,http-slowloris-check,http-tplink-dir-traversal,http-useragent-tester,http-userdir-enum,http-vuln-cve2006-3392,http-vuln-cve2009-3960,http-vuln-cve2010-0738,http-vuln-cve2010-2861,http-vuln-cve2011-3368,http-vuln-cve2012-1823,http-vuln-cve2013-0156,http-vuln-cve2013-7091,http-vuln-cve2014-2127,http-vuln-wnr1000-creds --script=http-apache-negotiation --script-args http-apache-negotiation.root=/root/ --script http-auth --script-args http-auth.path=/login --script http-awstatstotals-exec.nse --script-args \'http-awstatstotals-exec.cmd=\"uname -a\", http-awstatstotals-exec.uri=/awstats/index.php\' --script http-barracuda-dir-traversal --script-args http-max-cache-size=5000000 --script http-coldfusion-subzero --script-args basepath=/cf/ --script=http-drupal-modules --script-args http-drupal-modules.root="/path/",http-drupal-modules.number=1000 --script http-litespeed-sourcecode-download --script-args http-litespeed-sourcecode-download.uri=/phpinfo.php --script http-ntlm-info --script-args http-ntlm-info.root=/root/ --script http-vuln-cve2011-3192.nse --script-args http-vuln-cve2011-3192.hostname=nmap.scanme.org  -iL '+directory+'/HTTP8080.txt')        
                        try:
                                for host in pentest.all_hosts(): #loop to print and store the results by host and port
                                        print('-------------' + host +'---------------------------') #tag
                                        lport = pentest[host]['tcp'].keys() #new list with all the tcp ports in each host
                                        for port in lport: #this section looks for each possible port in the list above 
                                                status = str(pentest[host]['tcp'][port]['state']) #store the state of each port in status list
                                                if 'open' in status: #condition to detect open ports 
                                                        print ('checking on '+ host + 'Port 8080') #printing if it is open
                                                        host = str(host) #change the type
                                                        product = str(pentest[host]['tcp'][port]['product']) #this option allows to know the service
                                                        version = str(pentest[host]['tcp'][port]['version']) #this option allows to know the version
                                                        name = str(pentest[host]['tcp'][port]['name']) #this option allows to know more details for the service
                                                        script = str(pentest[host]['tcp'][port]['script']) #any extra information to fill the report
                                                        f = open(directory+'/collector/http/HTTPCollector.txt','a') #file containing all open porst by host 
                                                        list_scripts = script.split(", \'") #separator for each script output
                                                        f.write("\n#########################################################\n")
                                                        for line in list_scripts:
                                                                f.write('Nmap 6.47 '+host + ' ' + str(port) + ' ' + product + ' ' + version + '\n\n\n' + line +'\n\n\n\n')  #printing each script in the file              
                        except KeyError as e:
                                print ("Something wrong with nmap \(No results for scripts\)")
                                pass                
                        f1 = open(directory+'/logs/logHTTP', 'a')
                        ts = time.time()
                        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                        timestamp = str(st)  
                        f1.write('Nmap Collector Finished Port 8080 = ' + timestamp +"\n\n")                               

        print ("*******HTTP collector has finished please check the results in "+directory+"/collector/http/HTTPCollector.txt **********")
        f1 = open(directory+'/logs/logHTTP', 'a')
        ts = time.time()
        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
        timestamp = str(st)  
        f1.write('HTTP Collector Finished = ' + timestamp +"\n\n")        


def Check_SSL ():
        import datetime
        import time  
        import os.path
        import nmap
        print ("""\n\n\nThis script needs the following tools to work:
                        SSLscan
                        nmap scripts for HTTP
        All of them should be in the system path\n\n\n""")
        f = open('/tmp/directory.txt', 'r')
        directory = f.read()
        directory = str(directory)        
        f1 = open(directory+'/logs/logSSL', 'a')
        time.sleep(5)
        ts = time.time()                
        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')        
        timestamp = str(st)  
        f1.write('SSL Collector Started Port 443 = ' + timestamp +"\n\n")        
        print("*************Looking for files in discovery folder**************")
        HttpFile = os.path.isfile(directory+"/HTTPS443.txt")
        if HttpFile != False:
                #Check for the directory and creates it
                if not os.path.exists(directory+"/collector/https"):
                        os.mkdir(directory+"/collector/https")
                else:                
                        f1 = open(directory+'/logs/logSSL', 'a')
                        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                        timestamp = str(st)  
                        f1.write('SSLscan Collector Started Port 443 = ' + timestamp +"\n\n")                
                        f = open(directory+"/HTTPS443.txt", "r")
                        print ("Executing SSLscan on 443")
                        for line in f:
                                line = line.rstrip('\n')
                                from subprocess import Popen, PIPE
                                cmd = "sslscan --show-certificate --show-client-cas --no-colour " + line +" >> "+directory+"/collector/https/HTTPSCollector.txt"
                                print (cmd)
                                command = Command(cmd)
                                command.run(timeout=6000)                        
                                f = open(directory+'/collector/https/HTTPSCollector.txt','a') #file containing all open porst by host 
                                f.write("\n########################################################################################\n")
                        f1 = open(directory+'/logs/logSSL', 'a')
                        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                        timestamp = str(st)  
                        f1.write('SSLscan Collector Finished Port 443 = ' + timestamp +"\n\n")
                        f1.write('SSL nmap Collector Started Port 443 = ' + timestamp +"\n\n")  
                        print ("\n\n\n***********Executing all nmap scripts in HTTP port 443********\n\n\n")
                        time.sleep(1)
                        pentest = nmap.PortScanner() #new type of scan                
                        pentest.scan(arguments='-sV -Pn -sC -vvv -p 443 -T4 --script=ssl-enum-ciphers,ssl-known-key,tls-nextprotoneg  -iL '+directory+'/HTTPS443.txt')        
                        try:
                                for host in pentest.all_hosts(): #loop to print and store the results by host and port
                                        print('-------------' + host +'---------------------------') #tag
                                        lport = pentest[host]['tcp'].keys() #new list with all the tcp ports in each host
                                        for port in lport: #this section looks for each possible port in the list above 
                                                status = str(pentest[host]['tcp'][port]['state']) #store the state of each port in status list
                                                if 'open' in status: #condition to detect open ports 
                                                        print ('checking on '+ host + ' Port 443') #printing if it is open
                                                        host = str(host) #change the type
                                                        product = str(pentest[host]['tcp'][port]['product']) #this option allows to know the service
                                                        version = str(pentest[host]['tcp'][port]['version']) #this option allows to know the version
                                                        name = str(pentest[host]['tcp'][port]['name']) #this option allows to know more details for the service
                                                        script = str(pentest[host]['tcp'][port]['script']) #any extra information to fill the report
                                                        f = open(directory+'/collector/https/HTTPSCollector.txt','a') #file containing all open porst by host 
                                                        list_scripts = script.split(", \'")
                                                        f.write("\n#########################################################\n")
                                                        for line in list_scripts:
                                                                f.write(host + ' ' + str(port) + ' ' + product + ' ' + version + '\n\n\n' + line +'\n\n\n\n')                 
                        except KeyError as e:
                                print ("Something wrong with nmap \(No results for scripts\)")
                                pass
                        print ("""Executing Nikto on 443""")
                        f = open(directory+'/collector/https/HTTPSCollector.txt','a') #file containing all open porst by host 
                        f.write("\n#########################################################\n")                
                        f1 = open(directory+'/logs/logSSL', 'a')
                        ts = time.time()
                        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                        timestamp = str(st)        
                        f1.write('Nikto Collector Started Port 443 = ' + timestamp +"\n\n")                
                        f2 = open(directory+"/HTTPS443.txt", "r")
                        for line in f2:
                                line = line.rstrip('\n')
                                from subprocess import Popen, PIPE
                                cmd = "nikto -host " + "https://"+line+" >> "+directory+"/collector/https/HTTPSCollector.txt"
                                print (cmd)
                                command = Command(cmd)
                                command.run(timeout=600)
                                f = open(directory+'/collector/https/HTTPSCollector.txt','a') #file containing all open porst by host
                                f.write("\n#########################################################\n")
                                f.write("\n\n"+ cmd + "\n\n\n") 
                        f1 = open(directory+'/logs/logSSL', 'a')
                        ts = time.time()
                        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                        timestamp = str(st)  
                        f1.write('Nikto Collector Finished Port 443 = ' + timestamp +"\n\n")               
        else:
                print ('No HTTPS services to test')
                f1 = open(directory+'/logs/logSSL', 'a')
                st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                timestamp = str(st)  
                f1.write('No HTTPS services to test = ' + timestamp +"\n\n")                

        print ("\n\n*******HTTPS collector has finished please check the results HTTPSCollector.txt **********\n\n")
        f1 = open(directory+'/logs/logSSL', 'a')
        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
        timestamp = str(st)  
        f1.write('HTTPS collector has finished = ' + timestamp +"\n\n")        


def Check_DNS ():
        import os.path
        import datetime
        import time        
        print ("""\n\n\nThis script needs the following tools to work:
                        DNS Kali tools (dnsenum, dnsrecon, fierce)
                        nmap scripts for DNS
        All of them should be in the system path\n\n\n""")
        time.sleep(1)
        f = open('/tmp/directory.txt', 'r')
        directory = f.read()
        directory = str(directory)        
        f1 = open(directory+'/logs/logDNS', 'a')
        ts = time.time()                
        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')        
        timestamp = str(st)  
        f1.write('DNS Collector Started Port 53 = ' + timestamp +"\n\n")
        print ("Please provide the domain")
        domain = input ("Domain: ")
        domain = str(domain)
        time.sleep(5)
        print("*************Looking for files in discovery folder**************")
        HttpFile = os.path.isfile(directory+"/DNS53.txt")
        if HttpFile != False:
                os.mkdir(directory+"/collector/dns")
                f1 = open(directory+'/logs/logDNS', 'a')
                st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                timestamp = str(st)  
                f1.write('dnsenum Collector Started Port 53 = ' + timestamp +"\n\n")                
                f = open(directory+"/DNS53.txt", "r")
                print ("Executing dnsenum on 53")
                time.sleep(5)
                for line in f:
                        line = line.rstrip('\n')
                        from subprocess import Popen, PIPE
                        cmd = "dnsenum -dnsserver "+line+" --nocolor "+domain
                        print (cmd)
                        p = Popen(cmd , shell=True, stdout=PIPE, stderr=PIPE)
                        out, err = p.communicate()
                        f = open(directory+'/collector/dns/DNSCollector.txt','a') #file containing all open porst by host 
                        Httpsout = out.rstrip()
                        HttpsoutTxt = str(Httpsout,'ascii')
                        f.write("\n#########################################################\n")
                        f.write("dnsenum.pl VERSION:1.2.3 \n"+ cmd + "\n"+ HttpsoutTxt +"\n\n\n")
                f1 = open(directory+'/logs/logDNS', 'a')
                st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                timestamp = str(st)  
                f1.write('dnsenum Collector Finished Port 53 = ' + timestamp +"\n\n")
                f1.write('dnsrecon Collector Started Port 53 = ' + timestamp +"\n\n")
                f1 = open(directory+'/logs/logDNS', 'a')
                st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                timestamp = str(st)  
                f1.write('dnsrecon Collector Started Port 53 = ' + timestamp +"\n\n")                
                f = open(directory+"/DNS53.txt", "r")
                print ("Executing dnsrecon on 53")
                time.sleep(5)
                for line in f:
                        line = line.rstrip('\n')
                        from subprocess import Popen, PIPE
                        cmd = "dnsrecon -d "+domain+" -D /usr/share/dnsrecon/namelist.txt -t std,axfr -n "+line
                        print (cmd)
                        p = Popen(cmd , shell=True, stdout=PIPE, stderr=PIPE)
                        out, err = p.communicate()
                        f = open(directory+'/collector/dns/DNSCollector.txt','a') #file containing all open porst by host 
                        Httpsout = out.rstrip()
                        HttpsoutTxt = str(Httpsout,'ascii')
                        f.write("\n#########################################################\n")
                        f.write("dnsrecon Version: 0.8.8 \n"+ cmd + "\n"+ HttpsoutTxt +"\n\n\n")
                f1 = open(directory+'/logs/logDNS', 'a')
                st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                timestamp = str(st)  
                f1.write('dnsrecon Collector Finished Port 53 = ' + timestamp +"\n\n")
                f1 = open(directory+'/logs/logDNS', 'a')
                st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                timestamp = str(st)  
                f1.write('dnstracer Collector Started Port 53 = ' + timestamp +"\n\n")                
                f = open(directory+"/DNS53.txt", "r")
                print ("Executing dnstracer on 53")
                time.sleep(5)
                for line in f:
                        line = line.rstrip('\n')
                        from subprocess import Popen, PIPE
                        cmd = "dnstracer -v "+line
                        print (cmd)
                        p = Popen(cmd , shell=True, stdout=PIPE, stderr=PIPE)
                        out, err = p.communicate()
                        f = open(directory+'/collector/dns/DNSCollector.txt','a') #file containing all open porst by host 
                        Httpsout = out.rstrip()
                        HttpsoutTxt = str(Httpsout,'ascii')
                        f.write("\n#########################################################\n")
                        f.write("DNSTRACER version: 1.8.1 \n"+ cmd + "\n"+ HttpsoutTxt +"\n\n\n")
                f1 = open(directory+'/logs/logDNS', 'a')
                st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                timestamp = str(st)  
                f1.write('DNSTRACER Collector Finished Port 53 = ' + timestamp +"\n\n")                
                f1.write('DNS nmap Collector Started Port 53 = ' + timestamp +"\n\n")                
                print ("\n\n***********Executing all nmap scripts in DNS port 53********\n\n")
                import nmap
                pentest = nmap.PortScanner() #new type of scan                
                pentest.scan(arguments='-sU -Pn -sC -vvv -p 53 -T5 --script dns-nsid,dns-random-srcport,dns-random-txid,dns-recursion,dns-update,dns-zeustracker,dns-zone-transfer --script dns-cache-snoop.nse --script-args \'dns-cache-snoop.mode=timed,dns-cache-snoop.domains={google.com,facebook.com,twitter.com}\' --script dns-check-zone --script-args=\'dns-check-zone.domain='+domain+'\''+' --script=dns-nsec3-enum --script-args dns-nsec3-enum.domains='+domain+' --script dns-nsec-enum --script-args dns-nsec-enum.domains='+domain+' --script dns-brute '+ domain+'  -iL '+directory+'/DNS53.txt')        
                try:
                        for host in pentest.all_hosts(): #loop to print and store the results by host and port
                                print('-------------' + host +'---------------------------') #tag
                                lport = pentest[host]['tcp'].keys() #new list with all the tcp ports in each host
                                for port in lport: #this section looks for each possible port in the list above 
                                        status = str(pentest[host]['tcp'][port]['state']) #store the state of each port in status list
                                        if 'open' in status: #condition to detect open ports 
                                                print ('checking on '+ host + ' Port 53') #printing if it is open
                                                host = str(host) #change the type
                                                product = str(pentest[host]['tcp'][port]['product']) #this option allows to know the service
                                                version = str(pentest[host]['tcp'][port]['version']) #this option allows to know the version
                                                name = str(pentest[host]['tcp'][port]['name']) #this option allows to know more details for the service
                                                script = str(pentest[host]['tcp'][port]['script']) #any extra information to fill the report
                                                f = open(directory+'/collector/dns/DNSCollector.txt','a') #file containing all open porst by host 
                                                list_scripts = script.split(", \'")
                                                f.write("\n#########################################################\n")
                                                for line in list_scripts:
                                                        f.write(host + ' ' + str(port) + ' ' + product + ' ' + version + '\n\n\n' + line +'\n\n\n\n')                 
                except KeyError as e:
                        print ("Something wrong with nmap \(No results for scripts\)")
                        pass
                f1 = open(directory+'/logs/logDNS', 'a')
                st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                timestamp = str(st)
                f1.write('nmap Collector Finished Port 53 = ' + timestamp +"\n\n")
                f1.write('fierce Collector Started Port 53 = ' + timestamp +"\n\n")                
                f = open(directory+"/DNS53.txt", "r")
                print ("\n\n********** \n\n Executing fierce on 53 this tool is way too slow, so go for another coffee :\) \n\n******\n\n")
                for line in f:
                        line = line.rstrip('\n')
                        from subprocess import Popen, PIPE
                        cmd = "fierce -dns "+domain+" -dnsserver "+line+" -wordlist /usr/share/dnsrecon/namelist.txt -threads 10" + " >> "+directory+"/collector/dns/DNSCollector.txt"
                        print (cmd)
                        command = Command(cmd)
                        command.run(timeout=600)
                        f = open(directory+'/collector/dns/DNSCollector.txt','a') #file containing all open porst by host 
                        f.write("\n#########################################################\n")
                        f.write("fierce Version 0.9.9 - Beta 03/24/2007 \n"+ cmd + "\n\n\n")
                f1 = open(directory+'/logs/logDNS', 'a')
                st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                timestamp = str(st)  
                f1.write('fierce Collector Finished Port 53 = ' + timestamp +"\n\n")                              
        else:
                print ('No DNS services to test')
                f1 = open(directory+'/logs/logDNS', 'a')
                st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                timestamp = str(st)  
                f1.write('No DNS services to test = ' + timestamp +"\n\n")                

        print ("*******DNS collector has finished please check the results DNSCollector.txt **********")
        f1 = open(directory+'/logs/logDNS', 'a')
        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
        timestamp = str(st)  
        f1.write('DNS collector has finished = ' + timestamp +"\n\n")         

def Check_SNMP():
        import datetime
        import time
        import nmap
        print ("""\n\n\nThis script needs the following tools to work:
                        nmap scripts for SNMP
        All of them should be in the system path\n\n\n""")
        f = open('/tmp/directory.txt', 'r')
        directory = f.read()
        directory = str(directory)        
        import os.path
        print("*************Looking for files in discovery folder**************")
        HttpFile = os.path.isfile(directory+"/SNMP161.txt")
        if HttpFile != False:
                f1 = open(directory+'/logs/logSNMP', 'a')
                ts = time.time()                                
                st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                timestamp = str(st)  
                f1.write('SNMP Collector Started Port 161 = ' + timestamp +"\n\n")
                print ("This module has two options bruteforce and collector:")
                menu = {} #same kind of menu that the main menu
                menu['1']="BruteForce" 
                menu['2']="Collector" 
                print ('1', menu['1'])
                print ('2', menu['2'])
                selection=input("Please Select:")                
                if selection =='1': 
                        ts = time.time()                
                        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')        
                        timestamp = str(st)  
                        f1.write('SNMP Bruteforce Started Port 161 = ' + timestamp +"\n\n")
                        if not os.path.exists(directory+"/collector/snmp"):
                                os.mkdir(directory+"/collector/snmp")
                        else:
                                from subprocess import Popen, PIPE
                                f = open(directory+'/collector/snmp/SNMPCollector.txt','a') #file containing all open porst by host 
                                f.write("\n######################## Trying BruteForce With nmap #################################\n")  
                                cmd = "nmap --disable-arp-ping -n -Pn -p161 -sVU --script snmp-brute  --script-args snmp-brute.communitiesdb=snmp.txt -oN collector_snmp.out -iL "+directory+"/SNMP161.txt"
                                print ("Bruteforcing...")
                                p = Popen(cmd , shell=True, stderr=PIPE)
                                out, err = p.communicate()
                                cmd = "cat collector_snmp.out | grep \'report for\|Valid\' >> "+directory+"/collector/snmp/SNMPCollector.txt"
                                print ("########## Now time to export the results check at SNMPCollector.txt ###############")
                                p = Popen(cmd , shell=True, stderr=PIPE)
                                out, err = p.communicate()                                                             
                                f1 = open(directory+'/logs/logSNMP', 'a')
                                ts = time.time()
                                st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                                timestamp = str(st)
                                f1.write('SNMP Bruteforce Finished Port 161 = ' + timestamp +"\n\n")                 
                if selection == '2':
                        print ("Please provide the community string")
                        domain = input ("Community: ")
                        domain = str(domain)                        
                        ts = time.time()                
                        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')        
                        timestamp = str(st)
                        if not os.path.exists(directory+"/collector/snmp"):
                                os.mkdir(directory+"/collector/snmp")
                        else:
                                f = open(directory+"/SNMP161.txt", "r")
                                print ("Executing snmpcheck on 161")
                                for line in f:
                                        line = line.rstrip('\n')
                                        from subprocess import Popen, PIPE
                                        cmd = "snmpcheck -T 40 -w -t "+line+" -c "+domain                      
                                        print (cmd)
                                        p = Popen(cmd , shell=True, stdout=PIPE, stderr=PIPE)
                                        out, err = p.communicate()
                                        f = open(directory+'/collector/snmp/SNMPCollector.txt','a') #file containing all open porst by host 
                                        Httpsout = out.rstrip()
                                        HttpsoutTxt = str(Httpsout,'ascii')
                                        f.write("\n#########################################################\n")
                                        f.write("snmpcheck v1.8 - SNMP enumerator \n"+ cmd + "\n"+ HttpsoutTxt +"\n\n\n")
                                f1 = open(directory+'/logs/logSNMP', 'a')
                                ts = time.time()
                                st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                                timestamp = str(st)         
                                pentest = nmap.PortScanner() #new type of scan                
                                pentest.scan(arguments='-Pn -vv -n -p161 -sVU -T4 --script snmp-interfaces,snmp-netstat,snmp-processes,snmp-sysdescr,snmp-win32-services,snmp-win32-shares,snmp-win32-software,snmp-win32-users -iL '+directory+'/SNMP161.txt')        
                                try:
                                        for host in pentest.all_hosts(): #loop to print and store the results by host and port
                                                print('-------------' + host +'---------------------------') #tag
                                                lport = pentest[host]['tcp'].keys() #new list with all the tcp ports in each host
                                                for port in lport: #this section looks for each possible port in the list above 
                                                        status = str(pentest[host]['tcp'][port]['state']) #store the state of each port in status list
                                                        if 'open' in status: #condition to detect open ports 
                                                                print ('checking on '+ host + ' Port 161') #printing if it is open
                                                                host = str(host) #change the type
                                                                product = str(pentest[host]['tcp'][port]['product']) #this option allows to know the service
                                                                version = str(pentest[host]['tcp'][port]['version']) #this option allows to know the version
                                                                name = str(pentest[host]['tcp'][port]['name']) #this option allows to know more details for the service
                                                                script = str(pentest[host]['tcp'][port]['script']) #any extra information to fill the report
                                                                f = open(directory+'/collector/snmp/SNMPCollector.txt','a') #file containing all open porst by host 
                                                                list_scripts = script.split(", \'")
                                                                f.write("\n#########################################################\n")
                                                                for line in list_scripts:
                                                                        f.write(host + ' ' + str(port) + ' ' + product + ' ' + version + '\n\n\n' + line +'\n\n\n\n')                 
                                except KeyError as e:
                                        print ("Something wrong with nmap \(No results for scripts\)")
                                        pass			
                                f1 = open(directory+'/logs/logSNMP', 'a')
                                ts = time.time()
                                st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                                timestamp = str(st)
                                f1.write('SNMP Bruteforce Finished Port 161 = ' + timestamp +"\n\n")
        print("*******SNMP collector has finished please check the results SNMPCollector.txt**********")
        f1 = open(directory+'/logs/logSNMP', 'a')
        ts = time.time()
        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
        timestamp = str(st)  
        f1.write('SNMP collector has finished = ' + timestamp +"\n\n")

def Check_LDAP():
        import datetime
        import time
        import nmap
        print ("""\n\n\nThis script needs the following tools to work:
                        nmap scripts 
                         for SMTP
        All of them should be in the system path\n\n\n""")
        f = open('/tmp/directory.txt', 'r')
        directory = f.read()
        directory = str(directory)        
        import os.path
        print("*************Looking for files in discovery folder**************")
        HttpFile = os.path.isfile(directory+"/LDAP389.txt")
        if HttpFile != False:
                f1 = open(directory+'/logs/logLDAP', 'a')
                ts = time.time()                                
                st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                timestamp = str(st)  
                f1.write('LDAP Collector Started Port 389 = ' + timestamp +"\n\n")
                print ("\n\nThis module has two options enumeration and bruteforce and collector (Authenticated):\n\n")
                menu = {} #same kind of menu that the main menu
                menu['1']="Enumeration" 
                menu['2']="BruteForce"
                menu['3']="Collector"
                print ('1', menu['1'])
                print ('2', menu['2'])
                print ('3', menu['3'])
                selection=input("Please Select:")                
                if selection =='1': 
                        ts = time.time()                
                        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')        
                        timestamp = str(st)  
                        f1.write('LDAP Enumeration Started Port 389 = ' + timestamp +"\n\n")
                        if not os.path.exists(directory+"/collector/ldap"):
                                os.mkdir(directory+"/collector/ldap")
                        else:                                                   
                                time.sleep(5)
                                pentest = nmap.PortScanner() #new type of scan                
                                pentest.scan(arguments="-sV -vv -pT:389 --script ldap-search --script ldap-rootdse -iL "+directory+"/LDAP389.txt")        
                                try:
                                        for host in pentest.all_hosts(): #loop to print and store the results by host and port
                                                print('-------------' + host +'---------------------------') #tag
                                                lport = pentest[host]['tcp'].keys() #new list with all the tcp ports in each host
                                                for port in lport: #this section looks for each possible port in the list above 
                                                        status = str(pentest[host]['tcp'][port]['state']) #store the state of each port in status list
                                                        if 'open' in status: #condition to detect open ports 
                                                                print ('checking on '+ host + ' Port 25,465,587') #printing if it is open
                                                                host = str(host) #change the type
                                                                product = str(pentest[host]['tcp'][port]['product']) #this option allows to know the service
                                                                version = str(pentest[host]['tcp'][port]['version']) #this option allows to know the version
                                                                name = str(pentest[host]['tcp'][port]['name']) #this option allows to know more details for the service
                                                                script = str(pentest[host]['tcp'][port]['script']) #any extra information to fill the report
                                                                f = open(directory+'/collector/ldap/LDAPCollector.txt','a') #file containing all open porst by host 
                                                                list_scripts = script.split(", \'")
                                                                f.write("\n#########################################################\n")
                                                                for line in list_scripts:
                                                                        f.write(host + ' ' + str(port) + ' ' + product + ' ' + version + '\n\n\n' + line +'\n\n\n\n')                 
                                except KeyError as e:
                                        print ("Something wrong with nmap \(No results for scripts\)")
                                        pass			
                                f1 = open(directory+'/logs/logLDAP', 'a')
                                ts = time.time()
                                st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                                timestamp = str(st)
                                f1.write('LDAP Enumeration Finished Port 389 = ' + timestamp +"\n\n")
                                print ("\n\n ************ LDAP Enumeration completed ********** \n\n")
                                print ("\n\n ************ Going back to Collector ********** \n\n")
                                time.sleep(5)
                if selection =='2': 
                        ts = time.time()                
                        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')        
                        timestamp = str(st)
                        time.sleep(5)
                        f1.write('LDAP Bruteforce Started Port 389 = ' + timestamp +"\n\n")
                        if not os.path.exists(directory+"/collector/ldap"):
                                os.mkdir(directory+"/collector/ldap")
                        else:
                                print ("Please provide the LDAP Information (domain name dc=domain,dc=net)")
                                dc1 = input ("domain name dc: ")
                                dc1 = str(dc1)
                                dc2 = input ("suffix dc: ")
                                dc2 = str(dc2) 
                                time.sleep(5)
                                pentest = nmap.PortScanner() #new type of scan                
                                pentest.scan(arguments="-sV -vv -pT:389 --script ldap-brute --script-args ldap.base=\"cn=users,dc="+dc1+",dc="+dc2+"\" -iL "+directory+"/LDAP389.txt")        
                                try:
                                        for host in pentest.all_hosts(): #loop to print and store the results by host and port
                                                print('-------------' + host +'---------------------------') #tag
                                                lport = pentest[host]['tcp'].keys() #new list with all the tcp ports in each host
                                                for port in lport: #this section looks for each possible port in the list above 
                                                        status = str(pentest[host]['tcp'][port]['state']) #store the state of each port in status list
                                                        if 'open' in status: #condition to detect open ports 
                                                                print ('checking on '+ host + ' Port 389') #printing if it is open
                                                                host = str(host) #change the type
                                                                product = str(pentest[host]['tcp'][port]['product']) #this option allows to know the service
                                                                version = str(pentest[host]['tcp'][port]['version']) #this option allows to know the version
                                                                name = str(pentest[host]['tcp'][port]['name']) #this option allows to know more details for the service
                                                                script = str(pentest[host]['tcp'][port]['script']) #any extra information to fill the report
                                                                f = open(directory+'/collector/ldap/LDAPCollector.txt','a') #file containing all open porst by host 
                                                                list_scripts = script.split(", \'")
                                                                f.write("\n#########################################################\n")
                                                                for line in list_scripts:
                                                                        f.write(host + ' ' + str(port) + ' ' + product + ' ' + version + '\n\n\n' + line +'\n\n\n\n')                 
                                except KeyError as e:
                                        print ("Something wrong with nmap \(No results for scripts\)")
                                        pass			
                                f1 = open(directory+'/logs/logLDAP', 'a')
                                ts = time.time()
                                st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                                timestamp = str(st)
                                f1.write('LDAP Brute Force Finished Port 389 = ' + timestamp +"\n\n")
                                print ("\n\n ************ LDAP Brute Force completed ********** \n\n")
                                print ("\n\n ************ Going back to Collector ********** \n\n")
                                time.sleep(5)                                
                if selection =='3': 
                        ts = time.time()                
                        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')        
                        timestamp = str(st) 
                        f1.write('LDAP Collector Authenticated Started Port 389 = ' + timestamp +"\n\n")
                        if not os.path.exists(directory+"/collector/ldap"):
                                os.mkdir(directory+"/collector/ldap")
                        else:
                                print ("Please provide the LDAP Information (user and password)")
                                user = input ("user: ")
                                user = str(user)
                                password = input ("password: ")
                                password = str(password) 
                                time.sleep(5)
                                pentest = nmap.PortScanner() #new type of scan                
                                pentest.scan(arguments="-sV -vv -pT:389 --script ldap-search --script-args \'ldap.username="+user+",ldap.password="+password+"\' -iL "+directory+"/LDAP389.txt")        
                                try:
                                        for host in pentest.all_hosts(): #loop to print and store the results by host and port
                                                print('-------------' + host +'---------------------------') #tag
                                                lport = pentest[host]['tcp'].keys() #new list with all the tcp ports in each host
                                                for port in lport: #this section looks for each possible port in the list above 
                                                        status = str(pentest[host]['tcp'][port]['state']) #store the state of each port in status list
                                                        if 'open' in status: #condition to detect open ports 
                                                                print ('checking on '+ host + ' Port 389') #printing if it is open
                                                                host = str(host) #change the type
                                                                product = str(pentest[host]['tcp'][port]['product']) #this option allows to know the service
                                                                version = str(pentest[host]['tcp'][port]['version']) #this option allows to know the version
                                                                name = str(pentest[host]['tcp'][port]['name']) #this option allows to know more details for the service
                                                                script = str(pentest[host]['tcp'][port]['script']) #any extra information to fill the report
                                                                f = open(directory+'/collector/ldap/LDAPCollector.txt','a') #file containing all open porst by host 
                                                                list_scripts = script.split(", \'")
                                                                f.write("\n#########################################################\n")
                                                                for line in list_scripts:
                                                                        f.write(host + ' ' + str(port) + ' ' + product + ' ' + version + '\n\n\n' + line +'\n\n\n\n')                 
                                except KeyError as e:
                                        print ("Something wrong with nmap \(No results for scripts\)")
                                        pass			
                                f1 = open(directory+'/logs/logLDAP', 'a')
                                ts = time.time()
                                st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                                timestamp = str(st)
                                f1.write('LDAP Collector Authenticated Finished Port 389 = ' + timestamp +"\n\n")
                                print ("\n\n ************ LDAP Collector Authenticated Completed ********** \n\n")
                                print ("\n\n ************ Going back to Collector ********** \n\n")
                                time.sleep(5)                                
        print("*******LDAP collector has finished please check the results LDAPCollector.txt**********")
        f1 = open(directory+'/logs/logLDAP', 'a')
        ts = time.time()
        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
        timestamp = str(st)  
        f1.write('LDAP collector has finished = ' + timestamp +"\n\n")



def Check_SMB():
        import datetime
        import time
        import nmap
        print ("""\n\nThis script needs the following tools to work:
                        enum4linux
                        winlanfoe.pl
        All of them should be in the system path\n\n""")
        time.sleep(5)
        f = open('/tmp/directory.txt', 'r')
        directory = f.read()
        directory = str(directory)        
        import os.path
        print("*************Looking for files in discovery folder**************")
        time.sleep(5)
        HttpFile = os.path.isfile(directory+"/SMB445.txt")
        if HttpFile != False:
                f1 = open(directory+'/logs/logSMB445', 'a')
                ts = time.time()                                
                st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                timestamp = str(st)  
                f1.write('SMB Collector Started Port 445 = ' + timestamp +"\n\n")
                print ("This module has two options NULL Sessions and Authenticated:")
                menu = {} #same kind of menu that the main menu
                menu['1']="NULL Sessions" 
                menu['2']="Authenticated" 
                print ('1', menu['1'])
                print ('2', menu['2'])
                selection=input("Please Select: ")                
                if selection =='1': 
                        ts = time.time()                
                        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')        
                        timestamp = str(st)  
                        f1.write('SMB445 NULL Sessions Started Port 445 = ' + timestamp +"\n\n")
                        time.sleep(5)
                        if not os.path.exists(directory+"/collector/smb"):
                                os.mkdir(directory+"/collector/smb")
                        else:
                                from subprocess import Popen, PIPE
                                time.sleep(1)
                                f = open(directory+'/collector/smb/SMB445Collector.txt','a') #file containing all open porst by host 
                                f2 = open(directory+"/SMB445.txt", "r")
                                for line in f2:
                                        line = line.rstrip('\n')                                
                                        f.write("\n######################## Trying NULL Sessions 445 #################################\n\n enum4linux v0.8.9 \n\n") 
                                        time.sleep(5)
                                        cmd = "enum4linux -a " + line +" > "+directory+"/collector/smb/smbtemp.txt"
                                        cmd2 = "enum4linux -a " + line +" >> "+directory+"/collector/smb/smball.txt"
                                        print ("Trying NULL Sessions...Come on Windows!!!")
                                        p = Popen(cmd , shell=True, stderr=PIPE)
                                        p = Popen(cmd2 , shell=True, stderr=PIPE)
                                        out, err = p.communicate()
                                        f.write("\n######################## Collected domain user from: "+ line + " #################################\n")
                                        cmd = "cat "+directory+"/collector/smb/smbtemp.txt"" | grep \'Domain Users\|Domain Name:\' | cut -d\" \" -f 8 >> "+ directory + "/collector/smb/SMB445Collector.txt"
                                        p = Popen(cmd , shell=True, stderr=PIPE)
                                        out, err = p.communicate()
                                        f.write("\n######################## Collected non domain user from: "+ line + " #################################\n")
                                        cmd = "cat "+directory+"/collector/smb/smbtemp.txt"" | grep 'index:' | cut -d" " -f 8 >> "+ directory + "/collector/smb/SMB445Collector.txt"
                                        p = Popen(cmd , shell=True, stderr=PIPE)
                                        out, err = p.communicate()
                                        f.write("\n######################## Collected domain membership from: "+ line + " #################################\n")
                                        cmd = "perl winlanfoe.pl "+directory+"/collector/smb/smbtemp.txt"" | grep \'Wrkgrp\|Domain\'>> "+ directory + "/collector/smb/SMB445Collector.txt"
                                        p = Popen(cmd , shell=True, stderr=PIPE)
                                        out, err = p.communicate()                                
                                        print ("########## Now time to export the results check at SMB445Collector.txt ###############")
                                        p = Popen(cmd , shell=True, stderr=PIPE)
                                        out, err = p.communicate()
                                        f = open(directory+'/collector/smb/SMB445Collector.txt','a') #file containing all open porst by host 
                                        f.write("\n#########################################################\n")                
                                print ("***********Executing all nmap scripts in SMB ports 445 and 139********")
                                time.sleep(5)
                                pentest = nmap.PortScanner() #new type of scan                
                                pentest.scan(arguments='-vv -sU -sS --script smb-enum-shares.nse --script smb-enum-users.nse --script smb-system-info.nse --script smb-security-mode.nse --script=smb-vuln-* --script smb-server-stats.nse --script smb-os-discovery.nse --script smb-enum-users.nse --script smb-mbenum --script smb-enum-processes.nse --script smb-enum-sessions.nse --script smb-enum-domains.nse --script=smb-print-text  --script-args=\"text=CT_pentest\" -p U:137,T:139,T:445  -iL '+directory+'/HTTP80.txt')        
                                try:
                                        for host in pentest.all_hosts(): #loop to print and store the results by host and port
                                                print('-------------' + host +'---------------------------') #tag
                                                lport = pentest[host]['tcp'].keys() #new list with all the tcp ports in each host
                                                for port in lport: #this section looks for each possible port in the list above 
                                                        status = str(pentest[host]['tcp'][port]['state']) #store the state of each port in status list
                                                        if 'open' in status: #condition to detect open ports 
                                                                print ('checking on '+ host + 'Ports 445,139,137') #printing if it is open
                                                                host = str(host) #change the type
                                                                product = str(pentest[host]['tcp'][port]['product']) #this option allows to know the service
                                                                version = str(pentest[host]['tcp'][port]['version']) #this option allows to know the version
                                                                name = str(pentest[host]['tcp'][port]['name']) #this option allows to know more details for the service
                                                                script = str(pentest[host]['tcp'][port]['script']) #any extra information to fill the report
                                                                f = open(directory+'/collector/smb/SMB445Collector.txt','a') #file containing all open porst by host 
                                                                list_scripts = script.split(", \'")
                                                                f.write("\n#########################################################\n")
                                                                for line in list_scripts:
                                                                        f.write(host + ' ' + str(port) + ' ' + product + ' ' + version + '\n\n\n' + line +'\n\n\n\n') 
                                except KeyError as e:
                                        print ("Something wrong with nmap \(No results for scripts\)")
                                        pass                                        
                        f1 = open(directory+'/logs/logSMB445', 'a')
                        ts = time.time()
                        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                        timestamp = str(st)
                        f1.write('SMB NULL Sessions Finished Port 445 = ' + timestamp +"\n\n")                 
                if selection == '2':
                        print ("""\n\nUser name and Password: 
                        
                                     Local Users: username
                                     Domain Users:  domain\\username                                                       
                                                         \n\n""")
                        username = input ("User: ")
                        username = str(username) 
                        password = input ("Password: ")
                        password = str(password)
                        ts = time.time()                
                        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')        
                        timestamp = str(st)
                        time.sleep(5)
                        if not os.path.exists(directory+"/collector/smb"):
                                os.mkdir(directory+"/collector/smb")
                        else:
                                f2 = open(directory+"/SMB445.txt", "r")
                                f = open(directory+'/collector/smb/SMB445Collector.txt','a')
                                print ("Executing Windows Enumeration on 445 Authenticated")
                                for line in f2:
                                        line = line.rstrip('\n')
                                        from subprocess import Popen, PIPE
                                        f.write("\n######################## Trying NULL Sessions 445 #################################\n\n enum4linux v0.8.9 \n\n")
                                        time.sleep(5)
                                        cmd = "enum4linux -a -u "+username+" -p "+ password + " " + line+" >> "+ directory + "/collector/smb/SMB445Collector.txt"
                                        print ("Trying Windows Enumeration Authententicated!!!")
                                        p = Popen(cmd , shell=True, stdout=PIPE, stderr=PIPE)
                                        out, err = p.communicate()
                                        f.write("\n#########################################################\n")
                                f1 = open(directory+'/logs/logSMB445', 'a')
                                ts = time.time()
                                st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                                timestamp = str(st)         
                                f1.write('SMB Authenticated Finished Port 445 = ' + timestamp +"\n\n")
        print("*******SMB collector has finished please check the results SMB445Collector.txt**********")
        f1 = open(directory+'/logs/logSMB445', 'a')
        ts = time.time()
        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
        timestamp = str(st)  
        f1.write('SMB collector has finished = ' + timestamp +"\n\n")   
        

def Check_SMTP():
        import datetime
        import time
        import nmap
        print ("""\n\n\nThis script needs the following tools to work:
                        smtp-user-snum
                        nmap scripts 
                         for SMTP
        All of them should be in the system path\n\n\n""")
        f = open('/tmp/directory.txt', 'r')
        directory = f.read()
        directory = str(directory)        
        import os.path
        print("*************Looking for files in discovery folder**************")
        HttpFile = os.path.isfile(directory+"/SMTP25.txt")
        if HttpFile != False:
                f1 = open(directory+'/logs/logSMTP', 'a')
                ts = time.time()                                
                st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                timestamp = str(st)  
                f1.write('SMTP Collector Started Port 25 = ' + timestamp +"\n\n")
                print ("This module has two options vulnerability scanner and exploit:")
                menu = {} #same kind of menu that the main menu
                menu['1']="Vuln Scanner" 
                menu['2']="Exploit" 
                print ('1', menu['1'])
                print ('2', menu['2'])
                selection=input("Please Select:")                
                if selection =='1': 
                        ts = time.time()                
                        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')        
                        timestamp = str(st)  
                        f1.write('SMTP Vuln Scanning Started Port 25 = ' + timestamp +"\n\n")
                        if not os.path.exists(directory+"/collector/smtp"):
                                os.mkdir(directory+"/collector/smtp")
                        else:
                                print ("Please provide the fake domain")
                                domain = input ("Domain: ")
                                domain = str(domain)                                
                                pentest = nmap.PortScanner() #new type of scan
                                time.sleep(5)
                                pentest.scan(arguments="--script smtp-commands.nse [--script-args smtp-commands.domain=<"+domain+">] --script=smtp-vuln-cve2010-4344 --script-args=\"smtp-vuln-cve2010-4344.exploit\" --script=smtp-vuln-cve2011-1764 -pT:25,465,587 --script=smtp-vuln-cve2011-1720 --script-args=\'smtp.domain=<"+domain+">\' -iL "+directory+"/SMTP25.txt")        
                                try:
                                        for host in pentest.all_hosts(): #loop to print and store the results by host and port
                                                print('-------------' + host +'---------------------------') #tag
                                                lport = pentest[host]['tcp'].keys() #new list with all the tcp ports in each host
                                                for port in lport: #this section looks for each possible port in the list above 
                                                        status = str(pentest[host]['tcp'][port]['state']) #store the state of each port in status list
                                                        if 'open' in status: #condition to detect open ports 
                                                                print ('checking on '+ host + ' Port 25,465,587') #printing if it is open
                                                                host = str(host) #change the type
                                                                product = str(pentest[host]['tcp'][port]['product']) #this option allows to know the service
                                                                version = str(pentest[host]['tcp'][port]['version']) #this option allows to know the version
                                                                name = str(pentest[host]['tcp'][port]['name']) #this option allows to know more details for the service
                                                                script = str(pentest[host]['tcp'][port]['script']) #any extra information to fill the report
                                                                f = open(directory+'/collector/smtp/SMTPCollector.txt','a') #file containing all open porst by host 
                                                                list_scripts = script.split(", \'")
                                                                f.write("\n#########################################################\n")
                                                                for line in list_scripts:
                                                                        f.write(host + ' ' + str(port) + ' ' + product + ' ' + version + '\n\n\n' + line +'\n\n\n\n')                 
                                except KeyError as e:
                                        print ("Something wrong with nmap \(No results for scripts\)")
                                        pass			
                                f1 = open(directory+'/logs/logSMTP', 'a')
                                ts = time.time()
                                st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                                timestamp = str(st)
                                f1.write('SMTP Vuln Sanning Finished Port 161 = ' + timestamp +"\n\n")                 
                if selection == '2':
                        print ("Please provide the fake domain")
                        domain = input ("Domain: ")
                        domain = str(domain)                        
                        ts = time.time()                
                        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')        
                        timestamp = str(st)
                        time.sleep(5)
                        if not os.path.exists(directory+"/collector/smtp"):
                                os.mkdir(directory+"/collector/smtp")
                        else:
                                f = open(directory+"/SMTP25.txt", "r")
                                print ("Executing smtp-users-enum on 25 VRFY")
                                for line in f:
                                        line = line.rstrip('\n')
                                        from subprocess import Popen, PIPE
                                        cmd = "smtp-user-enum -M VRFY -U users_smtp.txt -t "+line                     
                                        print (cmd)
                                        p = Popen(cmd , shell=True, stdout=PIPE, stderr=PIPE)
                                        out, err = p.communicate()
                                        f = open(directory+'/collector/smtp/SMTPCollector.txt','a') #file containing all open porst by host 
                                        Httpsout = out.rstrip()
                                        HttpsoutTxt = str(Httpsout,'ascii')
                                        f.write("\n#########################################################\n")
                                        f.write("smtp-user-enum v1.2 \n"+ cmd + "\n"+ HttpsoutTxt +"\n\n\n")
                                f1 = open(directory+'/logs/logSMTP', 'a')
                                ts = time.time()
                                st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                                timestamp = str(st) 
                                f1.write('SMTP VRFY finished = ' + timestamp +"\n\n")
                                f = open(directory+"/SMTP25.txt", "r")
                                print ("Executing smtp-users-enum on 25 EXPN")
                                for line in f:
                                        line = line.rstrip('\n')
                                        from subprocess import Popen, PIPE
                                        cmd = "smtp-user-enum -M EXPN -U users_smtp.txt -t "+line                     
                                        print (cmd)
                                        p = Popen(cmd , shell=True, stdout=PIPE, stderr=PIPE)
                                        out, err = p.communicate()
                                        f = open(directory+'/collector/smtp/SMTPCollector.txt','a') #file containing all open porst by host 
                                        Httpsout = out.rstrip()
                                        HttpsoutTxt = str(Httpsout,'ascii')
                                        f.write("\n#########################################################\n")
                                        f.write("smtp-user-enum v1.2 \n"+ cmd + "\n"+ HttpsoutTxt +"\n\n\n")
                                f1 = open(directory+'/logs/logSMTP', 'a')
                                ts = time.time()
                                st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                                timestamp = str(st) 
                                f1.write('SMTP EXPN finished = ' + timestamp +"\n\n") 
                                f = open(directory+"/SMTP25.txt", "r")
                                time.sleep(5)
                                print ("Executing smtp-users-enum on 25 RCPT")
                                for line in f:
                                        line = line.rstrip('\n')
                                        from subprocess import Popen, PIPE
                                        cmd = "smtp-user-enum.pl -M RCPT -U users.txt -t "+line                     
                                        print (cmd)
                                        p = Popen(cmd , shell=True, stdout=PIPE, stderr=PIPE)
                                        out, err = p.communicate()
                                        f = open(directory+'/collector/smtp/SMTPCollector.txt','a') #file containing all open porst by host 
                                        Httpsout = out.rstrip()
                                        HttpsoutTxt = str(Httpsout,'ascii')
                                        f.write("\n#########################################################\n")
                                        f.write("smtp-user-enum v1.2 \n"+ cmd + "\n"+ HttpsoutTxt +"\n\n\n")
                                f1 = open(directory+'/logs/logSMTP', 'a')
                                ts = time.time()
                                st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                                timestamp = str(st) 
                                print ("Please provide To")
                                mailto = input ("Mail to: ")
                                mailto = str(mailto) 
                                print ("Please provide RCPT")
                                mailrcpt = input ("RCPT: ")
                                mailrcpt = str(mailrcpt)                                
                                f1.write('SMTP RCPT finished = ' + timestamp +"\n\n") 
                                time.sleep(5)
                                pentest = nmap.PortScanner() #new type of scan                
                                pentest.scan(arguments="--script smtp-open-relay.nse --script-args smtp-open-relay.domain=<"+domain+">,smtp-open-relay.to=<"+mailto+">,smtp-open-relay.from=<"+mailrcpt+"> -vv -pT:25,465,587 -iL "+directory+"/SMTP25.txt")        
                                try:
                                        for host in pentest.all_hosts(): #loop to print and store the results by host and port
                                                print('-------------' + host +'---------------------------') #tag
                                                lport = pentest[host]['tcp'].keys() #new list with all the tcp ports in each host
                                                for port in lport: #this section looks for each possible port in the list above 
                                                        status = str(pentest[host]['tcp'][port]['state']) #store the state of each port in status list
                                                        if 'open' in status: #condition to detect open ports 
                                                                print ('checking on '+ host + ' Port 25,465,587') #printing if it is open
                                                                host = str(host) #change the type
                                                                product = str(pentest[host]['tcp'][port]['product']) #this option allows to know the service
                                                                version = str(pentest[host]['tcp'][port]['version']) #this option allows to know the version
                                                                name = str(pentest[host]['tcp'][port]['name']) #this option allows to know more details for the service
                                                                script = str(pentest[host]['tcp'][port]['script']) #any extra information to fill the report
                                                                f = open(directory+'/collector/smtp/SMTPCollector.txt','a') #file containing all open porst by host 
                                                                list_scripts = script.split(", \'")
                                                                f.write("\n#########################################################\n")
                                                                for line in list_scripts:
                                                                        f.write(host + ' ' + str(port) + ' ' + product + ' ' + version + '\n\n\n' + line +'\n\n\n\n')                 
                                except KeyError as e:
                                        print ("Something wrong with nmap \(No results for scripts\)")
                                        pass		
                                f1 = open(directory+'/logs/logSMTP', 'a')
                                ts = time.time()
                                st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                                timestamp = str(st)
                                f1.write('SMTP Exploit Finished Port 25 = ' + timestamp +"\n\n")
        print("*******SMTP collector has finished please check the results SMTPCollector.txt**********")
        f1 = open(directory+'/logs/logSMTP', 'a')
        ts = time.time()
        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
        timestamp = str(st)  
        f1.write('SMTP collector has finished = ' + timestamp +"\n\n")
        f = open(directory+"/SMTP25.txt", "r")
        time.sleep(5)
        print ("Executing smtp-users-enum on 25 RCPT")
        for line in f:
                line = line.rstrip('\n')
                from subprocess import Popen, PIPE
                cmd = "smtp-user-enum.pl -M RCPT -U users.txt -t "+line                     
                print (cmd)
                p = Popen(cmd , shell=True, stdout=PIPE, stderr=PIPE)
                out, err = p.communicate()
                f = open(directory+'/collector/smtp/SMTPCollector.txt','a') #file containing all open porst by host 
                Httpsout = out.rstrip()
                HttpsoutTxt = str(Httpsout,'ascii')
                f.write("\n#########################################################\n")
                f.write("smtp-user-enum v1.2 \n"+ cmd + "\n"+ HttpsoutTxt +"\n\n\n")        


def Check_Cisco():
        import datetime
        import time
        print ("""\n\n\nThis script needs the following tools to work:
                                cisco-torch
                All of them should be in the system path\n\n\n""")
        time.sleep(1)
        f = open('/tmp/directory.txt', 'r')
        directory = f.read()
        directory = str(directory)        
        f1 = open(directory+'/logs/logCISCO', 'a')        
        ts = time.time()                
        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')        
        timestamp = str(st)  
        f1.write('Cisco Collector Started All Common Ports = ' + timestamp +"\n\n")     
        f2 = open(directory+'/LiveIPs.txt', 'r')
        print("*************Cisco Scan Starting**************")
        time.sleep(5)
        os.mkdir(directory+"/collector/cisco")
        f1 = open(directory+'/logs/logCISCO', 'a')
        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
        timestamp = str(st)  
        f1.write('cisco-torch Collector Started All Common Ports = ' + timestamp +"\n\n")                
        print ("\n\n\n*************Cisco Scan Starting cisco-torch **************\n\n\n")
        time.sleep(5)
        for line in f2:
                line = line.rstrip('\n')
                from subprocess import Popen, PIPE
                cmd = "cisco-torch -A "+line
                print (cmd)
                p = Popen(cmd , shell=True, stdout=PIPE, stderr=PIPE)
                out, err = p.communicate()
                f = open(directory+'/collector/cisco/CISCOCollector.txt','a') #file containing all open porst by host 
                Httpsout = out.rstrip()
                HttpsoutTxt = str(Httpsout,'ascii')
                f.write("\n#########################################################\n")
                f.write("cisco-torch VERSION:0.4b \n"+ cmd + "\n"+ HttpsoutTxt +"\n\n\n")
        f1 = open(directory+'/logs/logCISCO', 'a')
        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
        timestamp = str(st)  
        f1.write('cisco-torch Collector Finished All Common Ports = ' + timestamp +"\n\n")        
        
def Check_VNC():
        import datetime
        import time
        import nmap
        import os.path
        import os
        print ("""\n\n\nThis script needs the following tools to work:
                        nmap scripts 
                         for VNC
        All of them should be in the system path\n\n\n""")
        time.sleep(5)
        f = open('/tmp/directory.txt', 'r')
        directory = f.read()
        directory = str(directory)      
        print("*************Looking for files in discovery folder**************")
        HttpFile = os.path.isfile(directory+"/VNC5900.txt")
        if HttpFile != False:
                f1 = open(directory+'/logs/logVNC', 'a')
                ts = time.time()                                
                st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                timestamp = str(st)  
                f1.write('VNC Collector Started Port 5900 and 5800 = ' + timestamp +"\n\n")                
                if not os.path.exists(directory+"/collector/vnc"):
                        os.mkdir(directory+"/collector/vnc")
                else:                                                   
                        time.sleep(5)
                        pentest = nmap.PortScanner() #new type of scan                
                        pentest.scan(arguments="-sV -vv -pT:5900,5800 -sV --script realvnc-auth-bypass -iL "+directory+"/VNC5900.txt") 
                        print ("**************** Nmap scripts for VNC *********************")
                        try:
                                for host in pentest.all_hosts(): #loop to print and store the results by host and port
                                        print('-------------' + host +'---------------------------') #tag
                                        lport = pentest[host]['tcp'].keys() #new list with all the tcp ports in each host
                                        for port in lport: #this section looks for each possible port in the list above 
                                                status = str(pentest[host]['tcp'][port]['state']) #store the state of each port in status list
                                                if 'open' in status: #condition to detect open ports 
                                                        print ('checking on '+ host + ' Port 5900 and 5800') #printing if it is open
                                                        host = str(host) #change the type
                                                        product = str(pentest[host]['tcp'][port]['product']) #this option allows to know the service
                                                        version = str(pentest[host]['tcp'][port]['version']) #this option allows to know the version
                                                        name = str(pentest[host]['tcp'][port]['name']) #this option allows to know more details for the service
                                                        script = str(pentest[host]['tcp'][port]['script']) #any extra information to fill the report
                                                        f = open(directory+'/collector/vnc/VNCCollector.txt','a') #file containing all open porst by host 
                                                        list_scripts = script.split(", \'")
                                                        f.write("\n#########################################################\n")
                                                        for line in list_scripts:
                                                                f.write(host + ' ' + str(port) + ' ' + product + ' ' + version + '\n\n\n' + line +'\n\n\n\n')                 
                        except KeyError as e:
                                print ("Something wrong with nmap \(No results for scripts\)")
                                pass			
                        f1 = open(directory+'/logs/logVNC', 'a')
                        ts = time.time()
                        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                        timestamp = str(st)
                        f1.write('VNC Collector Finished Port 5900 and 5800 = ' + timestamp +"\n\n")        

def Check_RDP():
        print ("""This script needs the following tools to work:
        
                        RDP-SEC-CHECK 
                        NMAP Scripts
                        
        All of them should be in the system path""")
        import os.path
        import nmap
        import datetime
        import time        
        f = open('/tmp/directory.txt', 'r')
        directory = f.read()
        directory = str(directory)
        print (directory)
        print("*************Looking for files in discovery folder**************")
        HttpFile = os.path.isfile(directory+"/RDP3389.txt")
        if HttpFile != False:
                if not os.path.exists(directory+"/collector/rdp"):
                        os.mkdir(directory+"/collector/rdp")
                else:
                        f1 = open(directory+'/logs/logRDP', 'a')
                        import datetime
                        import time
                        ts = time.time()                
                        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                        timestamp = str(st)        
                        f1.write('RDP Collector Started = ' + timestamp +"\n\n")                     
                        f2 = open(directory+"/RDP3389.txt", "r")
                        print ("Executing rdp-sec-check on port 3389")
                        f1 = open(directory+'/logs/logRDP', 'a')
                        ts = time.time()
                        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                        timestamp = str(st)        
                        f1.write('RDP Collector Started = ' + timestamp +"\n\n")                
                        for line in f2:
                                line = line.rstrip('\n')
                                from subprocess import Popen, PIPE
                                f = open(directory+'/collector/rdp/RDPCollector.txt','a') #file containing all open porst by host 
                                cmd = "perl rdp-sec-check.pl " + line +" >> "+directory+"/collector/rdp/RDPCollector.txt"
                                print (cmd)
                                p = Popen(cmd , shell=True, stdout=PIPE, stderr=PIPE)
                                out, err = p.communicate()  
                                Httpsout = out.rstrip()
                                HttpsoutTxt = str(Httpsout,'ascii')                                
                                f.write("\n\n\n#########################################################\n")
                                f.write("rdp-sec-check v0.9-beta  \n"+ cmd + "\n"+ HttpsoutTxt +"\n\n\n")
                time.sleep(5)
                import nmap
                pentest = nmap.PortScanner() #new type of scan
                pentest.scan(arguments='-sV -vv --script=rdp-ms12-020 -p 3389 -iL '+directory+'/RDP3389.txt') 
                time.sleep(5)
                try:
                        for host in pentest.all_hosts(): #loop to print and store the results by host and port
                                print('-------------' + host +'---------------------------') #tag
                                lport = pentest[host]['tcp'].keys() #new list with all the tcp ports in each host
                                for port in lport: #this section looks for each possible port in the list above 
                                        status = str(pentest[host]['tcp'][port]['state']) #store the state of each port in status list
                                        if 'open' in status: #condition to detect open ports 
                                                print ('checking on '+ host + 'Port 3389') #printing if it is open
                                                host = str(host) #change the type
                                                product = str(pentest[host]['tcp'][port]['product']) #this option allows to know the service
                                                version = str(pentest[host]['tcp'][port]['version']) #this option allows to know the version
                                                name = str(pentest[host]['tcp'][port]['name']) #this option allows to know more details for the service
                                                script = str(pentest[host]['tcp'][port]['script']) #any extra information to fill the report
                                                f = open(directory+'/collector/rdp/RDPCollector.txt','a') #file containing all open porst by host 
                                                list_scripts = script.split(", \'") #separator for each script output
                                                f.write("\n#########################################################\n")
                                                for line in list_scripts:
                                                        f.write('Nmap 6.47 '+host + ' ' + str(port) + ' ' + product + ' ' + version + '\n\n\n' + line +'\n\n\n\n')  #printing each script in the file              
                except KeyError as e:
                        print ("Something wrong with nmap \(No results for scripts\)")
                        pass                
                f1 = open(directory+'/logs/logRDP', 'a')
                ts = time.time()
                st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                timestamp = str(st)  
                f1.write('Nmap Collector Finished Port 3389 = ' + timestamp +"\n\n")                            
                print ("*******RDP collector has finished please check the results in "+directory+"/collector/rdp/RDPCollector.txt **********")
                f1 = open(directory+'/logs/logRDP', 'a')
                ts = time.time()
                st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                timestamp = str(st)  
                f1.write('RDP Collector Finished = ' + timestamp +"\n\n") 
                
                
def Check_IKE():
        print ("""\n\n\nThis script needs the following tools to work:

                        Ike-scan
                        
        All of them should be in the system path\n\n\n""")
        import os.path
        import nmap
        import datetime
        import time        
        f = open('/tmp/directory.txt', 'r')
        directory = f.read()
        directory = str(directory)
        print (directory)
        print("*************Looking for files in discovery folder**************")
        HttpFile = os.path.isfile(directory+"/IKE500.txt")
        if HttpFile != False:
                if not os.path.exists(directory+"/collector/ike"):
                        os.mkdir(directory+"/collector/ike")
                else:
                        f1 = open(directory+'/logs/logIKE', 'a')
                        import datetime
                        import time
                        ts = time.time()                
                        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                        timestamp = str(st)        
                        f1.write('IKE Collector Started = ' + timestamp +"\n\n")                     
                        f2 = open(directory+"/IKE500.txt", "r")
                        print ("Executing ike-scan on port 500 UDP")
                        f1 = open(directory+'/logs/logIKE', 'a')
                        ts = time.time()
                        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                        timestamp = str(st)        
                        f1.write('IKE Collector Started = ' + timestamp +"\n\n")                
                        for line in f2:
                                line = line.rstrip('\n')
                                from subprocess import Popen, PIPE
                                f = open(directory+'/collector/ike/IKECollector.txt','a') #file containing all open porst by host 
                                f3 = open(snmp.txt, 'r')
                                for idike in f3:
                                        cmd = "ike-scan -A -n "+idike+" "+ line
                                        print (cmd)
                                        p = Popen(cmd , shell=True, stdout=PIPE, stderr=PIPE)
                                        out, err = p.communicate()  
                                        Httpsout = out.rstrip()
                                        HttpsoutTxt = str(Httpsout,'ascii')                                
                                        f.write("\n\n\n#########################################################\n")
                                        f.write("ike-scan VERSION:1.9  \n"+ cmd + "\n"+ HttpsoutTxt +"\n\n\n")
                        f1 = open(directory+'/logs/logIKE', 'a')
                        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                        timestamp = str(st)  
                        f1.write('IKE Collector Finished Port 500 UDP = ' + timestamp +"\n\n")                                

def Check_Oracle():
        print ("""\n\n\nThis script needs the following tools to work:

                        tnscmd10g

        All of them should be in the system path\n\n\n""")
        import os.path
        import nmap
        import datetime
        import time        
        f = open('/tmp/directory.txt', 'r')
        directory = f.read()
        directory = str(directory)
        print (directory)
        print("*************Looking for files in discovery folder**************")
        HttpFile = os.path.isfile(directory+"/ORACLE1521.txt")
        if HttpFile != False:
                if not os.path.exists(directory+"/collector/oracle"):
                        os.mkdir(directory+"/collector/oracle")
                else:
                        f1 = open(directory+'/logs/logORACLE', 'a')
                        import datetime
                        import time
                        ts = time.time()                
                        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                        timestamp = str(st)        
                        f1.write('ORACLE Collector Started = ' + timestamp +"\n\n")                     
                        f2 = open(directory+"/ORACLE1521.txt", "r")
                        print ("Executing oracle on port 1521 UDP")
                        f1 = open(directory+'/logs/logORACLE', 'a')
                        ts = time.time()
                        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                        timestamp = str(st)        
                        f1.write('ORACLE Collector Started = ' + timestamp +"\n\n")                
                        for line in f2:
                                line = line.rstrip('\n')
                                from subprocess import Popen, PIPE
                                f = open(directory+'/collector/oracle/ORACLECollector.txt','a') #file containing all open porst by host 
                                cmd = "tnscmd10g version -h " + line
                                print (cmd)
                                p = Popen(cmd , shell=True, stdout=PIPE, stderr=PIPE)
                                out, err = p.communicate() 
                                Httpsout = out.rstrip()
                                HttpsoutTxt = str(Httpsout,'ascii')                                
                                f.write("\n\n\n#########################################################\n")
                                f.write("tnscmd10g VERSION:1.3  \n"+ cmd + "\n"+ HttpsoutTxt +"\n\n\n")
                        for line in f2:
                                line = line.rstrip('\n')
                                from subprocess import Popen, PIPE
                                f = open(directory+'/collector/oracle/ORACLECollector.txt','a') #file containing all open porst by host 
                                cmd = "tnscmd10g status -h " + line
                                print (cmd)
                                p = Popen(cmd , shell=True, stdout=PIPE, stderr=PIPE)
                                out, err = p.communicate() 
                                Httpsout = out.rstrip()
                                HttpsoutTxt = str(Httpsout,'ascii')
                                f.write("\n\n\n#########################################################\n")
                                f.write("tnscmd10g VERSION:1.3  \n"+ cmd + "\n"+ HttpsoutTxt +"\n\n\n")
                        f1 = open(directory+'/logs/logORACLE', 'a')
                        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                        timestamp = str(st)  
                        f1.write('ORACLE Collector Finished Port 1521 TCP = ' + timestamp +"\n\n")      
                        
                        
def Check_MSSQL():
        import datetime
        import time
        import nmap
        print ("""\n\n\nThis script needs the following tools to work:
                        nmap scripts 
                         for MSSQL
        All of them should be in the system path\n\n\n""")
        f = open('/tmp/directory.txt', 'r')
        directory = f.read()
        directory = str(directory)        
        import os.path
        print("*************Looking for files in discovery folder**************")
        HttpFile = os.path.isfile(directory+"/MSSQL1433.txt")
        if HttpFile != False:
                f1 = open(directory+'/logs/logMSSQL', 'a')
                ts = time.time()                                
                st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                timestamp = str(st)  
                f1.write('MSSQL Collector Started Port 1433 and 2433 = ' + timestamp +"\n\n")                
                if not os.path.exists(directory+"/collector/mssql"):
                        os.mkdir(directory+"/collector/mssql")
                else:                                                   
                        time.sleep(5)
                        pentest = nmap.PortScanner() #new type of scan                
                        pentest.scan(arguments="-vv -pT:1433,2433 -sV --script ms-sql-info --script-args mssql.instance-port=1433 --script broadcast-ms-sql-discover --script ms-sql-empty-password -iL "+directory+"/MSSQL1433.txt")        
                        try:
                                for host in pentest.all_hosts(): #loop to print and store the results by host and port
                                        print('-------------' + host +'---------------------------') #tag
                                        lport = pentest[host]['tcp'].keys() #new list with all the tcp ports in each host
                                        for port in lport: #this section looks for each possible port in the list above 
                                                status = str(pentest[host]['tcp'][port]['state']) #store the state of each port in status list
                                                if 'open' in status: #condition to detect open ports 
                                                        print ('checking on '+ host + ' Port 1433 and 2433') #printing if it is open
                                                        host = str(host) #change the type
                                                        product = str(pentest[host]['tcp'][port]['product']) #this option allows to know the service
                                                        version = str(pentest[host]['tcp'][port]['version']) #this option allows to know the version
                                                        name = str(pentest[host]['tcp'][port]['name']) #this option allows to know more details for the service
                                                        script = str(pentest[host]['tcp'][port]['script']) #any extra information to fill the report
                                                        f = open(directory+'/collector/mssql/MSSQLCollector.txt','a') #file containing all open porst by host 
                                                        list_scripts = script.split(", \'")
                                                        f.write("\n#########################################################\n")
                                                        for line in list_scripts:
                                                                f.write(host + ' ' + str(port) + ' ' + product + ' ' + version + '\n\n\n' + line +'\n\n\n\n')                 
                        except KeyError as e:
                                print ("Something wrong with nmap \(No results for scripts\)")
                                pass			
                        f1 = open(directory+'/logs/logMSSQL', 'a')
                        ts = time.time()
                        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                        timestamp = str(st)
                        f1.write('MSSQL Collector Finished Port 1433 and 2433 = ' + timestamp +"\n\n")         

def Check_FTP():
        import datetime
        import time
        import nmap
        import os.path
        import os
        print ("""\n\n\nThis script needs the following tools to work:
        
                        nmap scripts 
                         for FTP
                         
        All of them should be in the system path\n\n\n""")
        time.sleep(5)
        f = open('/tmp/directory.txt', 'r')
        directory = f.read()
        directory = str(directory)      
        print("*************Looking for files in discovery folder**************")
        HttpFile = os.path.isfile(directory+"/FTP21.txt")
        if HttpFile != False:
                f1 = open(directory+'/logs/logFTP', 'a')
                ts = time.time()                                
                st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                timestamp = str(st)  
                f1.write('FTP Collector Started Port FTP = ' + timestamp +"\n\n")                
                if not os.path.exists(directory+"/collector/ftp"):
                        os.mkdir(directory+"/collector/ftp")
                else:                                                   
                        time.sleep(5)
                        pentest = nmap.PortScanner() #new type of scan                
                        pentest.scan(arguments="-sV -vv -pT:21 -sV --script ftp-anon --script ftp-bounce --script ftp-bounce --script ftp-libopie --script ftp-vuln-cve2010-4221 -iL "+directory+"/FTP21.txt") 
                        print ("**************** Nmap scripts for VNC *********************")
                        try:
                                for host in pentest.all_hosts(): #loop to print and store the results by host and port
                                        print('-------------' + host +'---------------------------') #tag
                                        lport = pentest[host]['tcp'].keys() #new list with all the tcp ports in each host
                                        for port in lport: #this section looks for each possible port in the list above 
                                                status = str(pentest[host]['tcp'][port]['state']) #store the state of each port in status list
                                                if 'open' in status: #condition to detect open ports 
                                                        print ('checking on '+ host + ' Port 21') #printing if it is open
                                                        host = str(host) #change the type
                                                        product = str(pentest[host]['tcp'][port]['product']) #this option allows to know the service
                                                        version = str(pentest[host]['tcp'][port]['version']) #this option allows to know the version
                                                        name = str(pentest[host]['tcp'][port]['name']) #this option allows to know more details for the service
                                                        script = str(pentest[host]['tcp'][port]['script']) #any extra information to fill the report
                                                        f = open(directory+'/collector/ftp/FTPCollector.txt','a') #file containing all open porst by host 
                                                        list_scripts = script.split(", \'")
                                                        f.write("\n#########################################################\n")
                                                        for line in list_scripts:
                                                                f.write(host + ' ' + str(port) + ' ' + product + ' ' + version + '\n\n\n' + line +'\n\n\n\n')                 
                        except KeyError as e:
                                print ("Something wrong with nmap \(No results for scripts\)")
                                pass			
                        f1 = open(directory+'/logs/logFTP', 'a')
                        ts = time.time()
                        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                        timestamp = str(st)
                        f1.write('FTP Collector Finished Port FTP = ' + timestamp +"\n\n")          


def Check_SSH():
        import datetime
        import time
        import nmap
        import os.path
        import os
        print ("""\n\n\nThis script needs the following tools to work:

                        nmap scripts 
                         for SSH

        All of them should be in the system path\n\n\n""")
        time.sleep(5)
        f = open('/tmp/directory.txt', 'r')
        directory = f.read()
        directory = str(directory)      
        print("*************Looking for files in discovery folder**************")
        HttpFile = os.path.isfile(directory+"/SSH22.txt")
        if HttpFile != False:
                f1 = open(directory+'/logs/logSSH', 'a')
                ts = time.time()                                
                st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                timestamp = str(st)  
                f1.write('SSH Collector Started Port 22 = ' + timestamp +"\n\n")                
                if not os.path.exists(directory+"/collector/ssh"):
                        os.mkdir(directory+"/collector/ssh")
                else:                                                   
                        time.sleep(5)
                        pentest = nmap.PortScanner() #new type of scan                
                        pentest.scan(arguments="-sV -vv -pT:22 -sV --script ssh2-enum-algos --script ssh-hostkey --script sshv1 -iL "+directory+"/SSH22.txt") 
                        print ("**************** Nmap scripts for VNC *********************")
                        try:
                                for host in pentest.all_hosts(): #loop to print and store the results by host and port
                                        print('-------------' + host +'---------------------------') #tag
                                        lport = pentest[host]['tcp'].keys() #new list with all the tcp ports in each host
                                        for port in lport: #this section looks for each possible port in the list above 
                                                status = str(pentest[host]['tcp'][port]['state']) #store the state of each port in status list
                                                if 'open' in status: #condition to detect open ports 
                                                        print ('checking on '+ host + ' Port 21') #printing if it is open
                                                        host = str(host) #change the type
                                                        product = str(pentest[host]['tcp'][port]['product']) #this option allows to know the service
                                                        version = str(pentest[host]['tcp'][port]['version']) #this option allows to know the version
                                                        name = str(pentest[host]['tcp'][port]['name']) #this option allows to know more details for the service
                                                        script = str(pentest[host]['tcp'][port]['script']) #any extra information to fill the report
                                                        f = open(directory+'/collector/ssh/SSHCollector.txt','a') #file containing all open porst by host 
                                                        list_scripts = script.split(", \'")
                                                        f.write("\n#########################################################\n")
                                                        for line in list_scripts:
                                                                f.write(host + ' ' + str(port) + ' ' + product + ' ' + version + '\n\n\n' + line +'\n\n\n\n')                 
                        except KeyError as e:
                                print ("Something wrong with nmap (No results for scripts)")
                                pass			
                        f1 = open(directory+'/logs/logSSH', 'a')
                        ts = time.time()
                        st = datetime.datetime.fromtimestamp(ts).strftime('%Y-%m-%d %H:%M:%S')
                        timestamp = str(st)
                        f1.write('SSH Collector Finished Port SSH = ' + timestamp +"\n\n")         


def Check_All ():
        import time
        collec = 1
        print ("\n\n\n......................\n\n......................\n\n\nThe best option if you are in a hurry or \n\nyou just want this srcipt to do the boring job for you.....\n\n\n")
        time.sleep(5)
        print (".....ready, steady, go......")
        if collec == 1:
                time.sleep(1)
                Check_VNC()
                collec = 1
        if collec == 1:
                time.sleep(1)
                Check_SSL ()
                collec = 1
        if collec == 1:
                time.sleep(1)
                Check_DNS ()
                collec = 1
        if collec == 1:
                time.sleep(1)
                Check_SNMP ()
                collec = 1
        if collec == 1:
                time.sleep(1)
                Check_SMB()
                collec = 1
        if collec == 1:
                time.sleep(1)
                Check_SMTP()
                collec = 1    
        if collec == 1:
                time.sleep(1)
                Check_RDP()
                collec = 1
        if collec == 1:
                time.sleep(1)
                Check_LDAP()
                collec = 1   
        if collec == 1:
                time.sleep(1)
                Check_Oracle()
                collec = 1 
        if collec == 1:
                time.sleep(1)
                Check_MSSQL()
                collec = 1 
        if collec == 1:
                time.sleep(1)
                Check_FTP
                collec = 1 
        if collec == 1:
                time.sleep(1)
                Check_IKE
                collec = 1 
        if collec == 1:
                time.sleep(1)
                Check_SSH
                collec = 1                 
        if collec == 1:
                time.sleep(1)
                Check_HTTP()
                collec = 1                 
        print ("\n\n\n*******Collector has finished please check the results in Collector folder **********\n\n\n")



class Command(object):
        import subprocess
        import threading
        import os
        import signal
        from subprocess import Popen, PIPE        
        def __init__(self, cmd):
                self.cmd = cmd
                self.process = None

        def run(self, timeout):
                def target():                      
                        print ('Thread started')
                        self.process = subprocess.Popen(self.cmd, shell=True, preexec_fn=os.setsid)
                        self.process.communicate()
                        print ('Thread finished')

                thread = threading.Thread(target=target)
                thread.start()
                thread.join(timeout)
                if thread.is_alive():
                        print ('Timeout reached...')
                        os.killpg(self.process.pid, signal.SIGTERM)
                        thread.join()
                print (self.process.returncode)





main_menu() #the main function that calls the scanner and menu
                #This calls main_menu() 
