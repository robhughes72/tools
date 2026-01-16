This is a collection of network service enumeration tools I have built to assist with the scanning an enumeration phase of a Penetration test, most syntax for each tool is included in the tool comments sections, which will be displayed when running the tool with no arguments. 

Start with the host discovery and port scanning script, recon.sh, which is just a wrapper around nmap.

If you need to perform a host discovery, you enter the subnets and the tool will perform a ping sweep across the subnet. 

If external, or testing through routers that might not have ICMP (won't allow ping right...), put the subnet into a targets.txt file and run the port scan options (if scanning large, cloud based environments, use my Xenum script)

Start with top 20 for large networks, then top 100, full tcp, Fast UDP, default UDP. 

The tool will output all services into .txt files based on the service, which then then be fed into the enumeration tools. 

ie smb_security_audit.sh -L smb.txt

This will run the smb enumeration across the smb servers using the latest tools such as enum4linux-ng, smbmap etc.

If NMAP doesn't know what a service is, it will just assume it is a service that can run on a certain port, don't assume, use service_identifier.sh to try and enumerate the service. 

The idea here is to build a collection of tools that will assist with the scanning and enumeration phase of a pentest, then you corrolate the service versions to any known vulnerabilities or test for misconfigurations manually using the CVE database.. 

The you checkout exploitdb for exploitation, or checkout my compiled binaries or exploits repo's. 

Which is a Penetration test and not a vulnerability scan...right !!!