This is a collection of network service enumeration tools I have built to assist with the scanning and enumeration phase of a Penetration test, most syntax for each tool is included in the tool comments sections, which will be displayed when running the tool with no arguments. 

Start with the host discovery and port scanning script, recon.sh, which is just a wrapper around nmap -sS type scan (that's a syn scan if your curious, the one that works best) 

If you need to perform a host discovery, you enter the subnets and the tool will perform a ping sweep across the subnet. 

!!! Make sure you have authorization and a signed Statement / scope of work document before using any of these tools !!!!

If external, or testing through routers that might not allow ICMP (won't allow ping right...), put the subnet into a targets.txt file and run the port scan options (if scanning large, cloud based environments, use my Xenum script)

Start with top 20 for large networks, then top 100, full tcp, Fast UDP, default UDP. 

The tool will output all services into .txt files based on the service, which then then be fed into the enumeration tools. (Sometimes ssl / tls services don't get mapped accurately so you might still need to do some manual admin of these files). 

ie smb_security_audit.sh -L smb.txt

This will run the smb enumeration across the smb servers using the latest tools such as enum4linux-ng, smbmap etc.

If NMAP doesn't know what a service is, it will just assume it is a service that can run on a certain port, don't assume, use service_identifier.sh to try and enumerate the service, as this is how some clever network admins hide their services from attackers. 

The idea here is to build a collection of tools that will assist with the scanning and enumeration phase of a penetration test, then you corrolate the service versions to any known vulnerabilities using the CVE database, perform authentication brute force, password spraying or test for misconfigurations manually.

If anything has a CVE, then you checkout exploitdb etc for exploit code, or checkout my compiled binaries or exploits repo for some validation through light exploitation tools. 

Watch this space for updates and new tools and check out my other repos for other types of toolsets. 