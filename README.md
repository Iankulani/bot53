# bot53

<img width="524" height="536" alt="bott" src="https://github.com/user-attachments/assets/1c8a5230-1d29-49e9-aaec-bd60f2ea3f9b" />



Bot 53 is a comprehensive, multi-platform command-and-control (C2) simulation framework designed to demystify and demonstrate the mechanics of IP spoofing and DNS manipulation. It bridges the gap between theoretical network knowledge and practical application, offering a legal, controlled environment for network engineers, students, and seasoned cybersecurity professionals to test, learn, and harden their infrastructures against spoofing attacks.

The Core Philosophy: Education Through Simulation
Bot 53 was built on a singular principle: to demonstrate how trust relationships in network protocols can be exploited. Unlike malicious tools that obscure their functionality, Bot 53 is transparent. It serves as a pedagogical instrument, allowing users to visualize the packet-level changes required to alter a packet’s perceived origin and to intercept or manipulate DNS queries in real time.

The tool is designed to simulate the behavior of a malicious actor without requiring the user to manage complex, fragmented open-source libraries. By consolidating these capabilities into a single, unified interface, Bot 53 allows professionals to focus on the defensive implications—crafting firewall rules, configuring intrusion detection systems (IDS), and analyzing logs—rather than struggling with toolchain compatibility.

Feature 1: Advanced IP Spoofing Capabilities
At the heart of Bot 53 lies its robust IP spoofing engine. IP spoofing, the act of crafting packets with a falsified source IP address, remains a critical vector for Denial-of-Service (DoS) attacks and evasion techniques. Bot 53 allows users to safely execute spoofing within isolated lab environments to understand how these packets traverse networks.

The tool leverages raw socket programming and packet injection libraries (such as Scapy or libnet) to allow the user to craft packets with arbitrary source addresses. However, Bot 53 is not merely a packet generator; it includes intelligent spoofing logic.

Session Awareness: While IP spoofing is typically unidirectional, Bot 53 includes modules to analyze how stateful firewalls (like iptables or AWS Security Groups) react to asymmetric routing caused by spoofed traffic.

Protocol Support: Users can spoof TCP, UDP, and ICMP packets, adjusting TTL values, fragment offsets, and TCP flags to bypass basic security controls.

Educational Mode: When enabled, the tool overlays a real-time packet capture (PCAP) analysis, highlighting exactly which headers were modified and how upstream routers or intrusion prevention systems (IPS) would interpret the packet.

For network engineers, this feature is invaluable for stress-testing network access control lists (ACLs) and ensuring that ingress filtering (such as BCP 38) is correctly implemented across their infrastructure.

Feature 2: DNS Spoofing Demonstration
DNS is often referred to as the "phonebook of the internet," yet it remains one of the most vulnerable protocols in the stack. Bot 53 features a dedicated DNS Spoofing Module that demonstrates how an attacker can poison a local cache or respond faster than a legitimate DNS server to redirect traffic.

This module allows users to set up a man-in-the-middle (MITM) environment where they can:

Intercept DNS queries for specific domains (e.g., *.bankingcorp.com).

Respond with malicious A records (IP addresses) or NS records before the legitimate DNS server can reply.

Analyze DNSSEC validation failures to understand how cryptographic signing prevents such attacks.

The tool visualizes the race condition inherent in DNS spoofing, showing the user how timing and packet injection speed determine success. For students studying the OSCP or CEH curricula, this module provides a hands-on understanding of how DNS poisoning facilitates phishing attacks or internal lateral movement without relying on malware.

Feature 3: Universal Command Interface (Multi-Platform C2)
What sets Bot 53 apart from traditional network tools is its revolutionary interface layer. Recognizing that modern cybersecurity operations are decentralized, Bot 53 decouples the execution engine from the user interface. The tool acts as a bot (hence the name) that listens for commands across five major communication platforms: Telegram, Discord, WhatsApp, and Slack.

This architecture allows a user to execute complex spoofing commands or DNS attacks from their mobile device while on-site, or collaborate with a team across different time zones without needing direct SSH access to the host machine.

How it works:
The Listener: Bot 53 runs on a host machine (a Raspberry Pi, a cloud VM, or a laptop within a lab network).

The Interface: The user interacts with Bot 53 via a chat interface.

The Commands: The user sends JSON-formatted commands or natural language prompts (processed via a built-in NLP parser) to the bot.

Command Examples:

/spoof --src 192.168.1.100 --dst 10.0.0.1 --protocol tcp --port 443 – Launches a spoofed TCP handshake from a fake internal IP to a target.

/dns_spoof --interface eth0 --host victim.com --redirect 192.168.1.50 – Activates DNS spoofing for a specific domain, redirecting all requests on the local network to a specified honeypot.

/capture --filter "dns" --duration 60 – Captures 60 seconds of DNS traffic to verify the spoofing success.

This multi-platform support ensures that Bot 53 fits seamlessly into the workflow of modern red teams, SOC analysts, and network architects who rely on rapid communication channels for incident response.

Use Cases Across the Cybersecurity Spectrum
Bot 53 is not a monolithic tool designed for a single type of user. Its modular architecture caters to three distinct personas:

1. Network Engineers
For engineers managing enterprise or cloud infrastructure, validating security controls is paramount. Bot 53 allows engineers to simulate spoofing attacks from within the network to test the efficacy of Unicast Reverse Path Forwarding (uRPF) , Virtual Routing and Forwarding (VRF) isolation, and cloud security groups. If a network engineer can successfully spoof a packet to a critical server using Bot 53, they know their ACLs are misconfigured and require immediate patching.

2. Cybersecurity Students
For students pursuing certifications like Security+, CySA+, or practical ethical hacking courses, theoretical knowledge is rarely enough. Bot 53 serves as a safe, legal sandbox. Students can set up virtual labs (using VMware or VirtualBox) and use Bot 53 to execute the attacks they read about in textbooks. They can observe how DNS spoofing leads to credential harvesting or how IP spoofing bypasses simple IP-based allowlisting. The tool includes a "Logging Mode" that exports every action to a PDF report, allowing students to document their labs for portfolios or academic submissions.

3. Cyber Professionals (Red & Blue Teams)
For penetration testers and red teamers, time is the ultimate constraint. Bot 53 acts as a lightweight C2 agent that can be deployed quickly. Because it communicates via legitimate APIs (Telegram, Slack, Discord), its traffic blends in with common corporate collaboration tools, avoiding detection by network monitoring solutions that flag unusual ports or protocols.
For blue teamers (defenders), Bot 53 is an essential adversary simulation tool. Defenders can deploy Bot 53 within their SOC to run "purple team" exercises, testing how quickly their SIEM detects DNS spoofing anomalies or how their EDR responds to spoofed process injection attempts.

Ethical Considerations and Safety
Bot 53 is explicitly designed for authorized testing and educational purposes only. To prevent misuse, the tool includes a safety interlock:

Target Confirmation: Before executing any spoofing command, Bot 53 requires the user to input a "Target Authorization Hash" or run the tool in "Sandbox Mode" where traffic is confined to a virtualized network segment.

Banner Warnings: Upon launch, the tool displays a strict legal disclaimer outlining the penalties for unauthorized network intrusion under laws such as the Computer Fraud and Abuse Act (CFAA) and the GDPR.

Conclusion
Bot 53 represents the evolution of cybersecurity tooling. It moves beyond static, command-line-only utilities to become a dynamic, multi-platform framework that meets the user wherever they are—whether that is a terminal, a Slack channel, or a WhatsApp chat.

By combining the technical depth required for IP spoofing with the practical demonstration of DNS manipulation, and wrapping it in a modern, collaborative interface, Bot 53 empowers network engineers to harden their infrastructure, students to accelerate their learning curve, and professionals to execute sophisticated red team operations with surgical precision.

In an era where network trust is constantly under siege, understanding how to break that trust is the first step to securing it. Bot 53 is the key to that understanding.

# How to clone the repo
```bash
git clone https://github.com/Iankulani/bot53.git
cd bot53
``` 
# How to run
```bash
python bot53.py
```
[![Star History Chart](https://api.star-history.com/svg?repos=Iankulani/bot53&type=Date)](https://star-history.com/#Iankulani/bot53&Date)
