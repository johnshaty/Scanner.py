import nmap
import re
#geimport pandas as pd

ip_address_pattern = re.compile(r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$")
port_range_pattern = re.compile("([0-9]+)-([0-9]+)")

port_range = '1-65355'
nm = nmap.PortScanner()
host_list = []


class TargetHost:
    def __init__(self, ip, attributes=None):
        self.ip = ip
        if attributes is None:
            self.attributes = {}
        else:
            self.attributes = attributes

    def get_attributes(self, key):
        return self.attributes.get(key, None)

    def set_attribute(self, key, value):
        self.attributes[key] = value

    def __str__(self):
        return f"Target Host: {self.ip}, Attributes: {self.attributes} "

    # Validation to check IP is Real IP


while True:

    host_entered = input("\nEnter Host IPs Separated by commas to Scan: ")
    host_entered_list = host_entered.split(", ")
    

    validIP = True
    for IP in host_entered_list:
        if ip_address_pattern.search(IP):
            host_list.append(IP)
            print(f"{IP} is a valid IP address")

        # return host_entered

        else:
            validIP = False
            print("Enter Valid Target IP")

    if validIP:
        break
    else:
        print("Enter all valid target IPs")


host_objects = [TargetHost(ip) for ip in host_list]


# for host in host_objects:
#    print(host_objects)

def open_ports_scan(target_objs):
    for target in target_objs:
        nm.scan(hosts=target.ip, ports=port_range, arguments="-sT")
        
        target.set_attribute("Open Ports", [])
    

        pre_scan_result = nm[target.ip]

        for protocol in pre_scan_result.all_protocols():
            port_list = pre_scan_result[protocol].keys()

            for port in port_list:
                state = pre_scan_result[protocol][port]["state"]

                if state == "open":
                    open_ports = target.get_attributes("Open Ports")
                    open_ports.append(port)
                    target.set_attribute("Open Ports", open_ports)


    print("Open Ports Found -- Starting Main Scan ")


def main_scan(target_objs):

    for target in target_objs:
        host_ports =  target.get_attributes("Open Ports")
        nm.scan(hosts=target.ip, ports=str(host_ports), arguments="-Pn -sCV")

       
        target.set_attribute("Port Info", {})

        main_scan_result = nm[target.ip]
        for protocol in main_scan_result.all_protocols():
            port_list = main_scan_result[protocol].keys()

            for port in port_list:
                state = main_scan_result[protocol][port]["state"]

                if state == "open":

                    port_info = target.get_attributes("Port Info")

                    product = main_scan_result[protocol][port].get("product", "")
                    version = main_scan_result[protocol][port].get("version", "")

                    port_info[port] = {
                        "Protocol": protocol,
                        "Product": product,
                        "Version": version


                    }

                    target.set_attribute("Port Info", port_info)






open_ports_scan(host_objects)
main_scan(host_objects)

for host in host_objects:
    print(f"Target Host: {host.ip}\n")

    port_info = host.get_attributes("Port Info")
    for port, info in port_info.items():
        product_version = f"{info['Product']} {info['Version']}".strip()
        print(f"Port: {port}, Product + Version: {product_version}")
    print("---------------------------------------------------------")

