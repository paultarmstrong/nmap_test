import nmap

ns = nmap.PortScanner()
print("The nmap version is ")
print(ns.nmap_version())
ns.scan('192.168.1.0/24', '20-443', '-v')
print(ns.scaninfo())

print(ns.scanstats())

#print(ns.all_hosts())

print("---------------------------")
#print("Status of router")
#print(ns['192.168.1.1'].state())

#print("---------------------------")
#print("Protocols running on router")
#print(ns['192.168.1.1'].all_protocols())

for host in ns.all_hosts():
    if ns[host].state() == 'up':
        print('----------')
        print('Host : %s (%s)' % (host, ns[host].hostname()))
        print('State : %s' % ns[host].state())
        for proto in ns[host].all_protocols():
            print('Protocol : %s' % proto)

            lport = ns[host][proto].keys()
            lport.sort()
            for port in lport:
                print('port : %s\tstate : %s' % (port, ns[host][proto][port]['state']))
