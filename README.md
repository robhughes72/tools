This is a collection of network service enumeration tools, most syntax for each tool is included in the tool comments sections. 

Start with recon.sh (host discovery and port scanning) 

If you need to perform a host discovery, you enter the subnets and the tool will perform a ping sweep across the subnet. 

If external, or testing through routers that might not have ICMP, put the subnet into a targets.txt file and run the port scan options. 

Start with top 20 for large networks. 

The tool will output all services into .txt files based on the service, which then then be fed into the enumeration tools. 

ie smb_security_audit.sh -L smb.txt

will run the smb enumeration across the smb servers using the latest tools (at the time of writing) 

Some may scripts perform light exploitation to validate a finding, although most are just manual enumeration strings wrapped into bash or python scripts. 

The idea here is to build a collection of tools that will corrolate with an NMAP scan to encompass an all inclusive toolset for scanning and enumeration network services - whilst keeping the human in control. 