# OS Detection via TCP/IP Header Fingerprinting

A Python tool for **remote operating system fingerprinting** using TCP/IP header analysis.  
It identifies the likely OS of a target by examining subtle differences in TCP/IP stack behavior.

---

## **Overview**
This script performs **remote operating system fingerprinting** by analyzing characteristics of TCP/IP response headers.  
It uses subtle differences in how various operating systems implement TCP/IP stacks to infer the likely OS of a target.

---

## **How It Works**
Operating systems have distinct **default values** for several fields in their TCP/IP packets.  
By sending a TCP **SYN** packet and examining the response (typically a **SYN-ACK**), we can extract:

### **TTL (Time To Live)**
- Default initial TTL varies by OS:
  - `64` → Linux / FreeBSD
  - `128` → Windows
  - `255` → Cisco / network devices

### **TCP Window Size**
- The size of the receive buffer advertised by the host.
- Common defaults:
  - `32120`, `5840` → Linux/FreeBSD
  - `64240`, `65535` → Windows

### **DF (Don't Fragment) Bit**
- Indicates whether the packet can be fragmented.
- Most modern OSes set it; older ones (e.g., SCO Unix, OpenBSD) may not.

### **ToS (Type of Service)**
- Indicates packet priority. Some OSes or network appliances use characteristic values.

### **Detection Method**
The script:
1. Takes an **IP, domain, or URL** as input.
2. Resolves it to an **IP address** if necessary.
3. Sends a crafted **TCP SYN packet** (using Scapy) to port `80`.
4. Analyzes the **TTL, TCP Window Size, DF flag, and ToS** from the response.
5. Matches these against a **small signature database** to infer the OS.


## **Flow Diagram**

```
      +-------------------------+
      |   User Input (IP/URL)   |
      +-----------+-------------+
                  |
                  v
      +-----------+-------------+
      |  Resolve to IP address  |
      +-----------+-------------+
                  |
                  v
      +-----------+-------------+
      | Send TCP SYN packet (80)|
      +-----------+-------------+
                  |
                  v
      +-----------+-------------+
      | Capture SYN-ACK response|
      +-----------+-------------+
                  |
                  v
      +------------------------------+
      | Extract header fields:       |
      |  - TTL                       |
      |  - TCP Window Size           |
      |  - DF (Don't Fragment) flag  |
      |  - ToS (Type of Service)     |
      +------------------------------+
                  |
                  v
      +-----------+-------------+
      | Match against signature |
      |     database            |
      +-----------+-------------+
                  |
                  v
      +-------------------------+
      | Output Likely OS & Info |
      +-------------------------+
```

````

---

## **Use Cases**
- Quick OS fingerprinting for **network reconnaissance**.
- Educational purposes to demonstrate **TCP/IP stack fingerprinting**.
- Security testing in **authorized environments** only.

---

## **Installation**
Requires Python 3 and the following libraries:
```bash
pip install scapy termcolor
````

---

## **Usage**

Run the script with root privileges (required for raw packet sending):

```bash
sudo python detect_os.py <IP/Domain/URL>
```

**Example:**

```bash
sudo python detect_os.py https://example.com
```

**Output:**

```
[+] example.com resolved to 93.184.216.34
[+] Probing 93.184.216.34...

[DEBUG] TTL: 64, Window Size: 32120, DF: True, ToS: 0
Likely OS: Linux/FreeBSD
```

---

## **Limitations**

* Accuracy depends on:

  * Network path (TTL can be decremented by intermediate hops).
  * Targets behind **firewalls or CDNs** may reveal the OS of the edge server.
  * Some OSes use **dynamic TCP window scaling**, making detection harder.
* For advanced fingerprinting, use tools like **Nmap** which perform multi-probe analysis.

---

## **Disclaimer**

This tool is for **educational and authorized security testing purposes only**.
Do not use it on systems you do not own or have explicit permission to scan.

