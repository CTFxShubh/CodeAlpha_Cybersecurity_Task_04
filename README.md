# CodeAlpha_Cybersecurity_Task_04
## Network Intrusion Detection System

Create a network-based intrusion detection system using Suricata. Below are the steps (compatible with Kali Linux):

### Installation of Suricata:

Execute the following command to install Suricata:
```bash
sudo apt-get install suricata
```

### Updating the Emerging Threats Open Ruleset:
Run the command below to update the ruleset:
```bash
sudo suricata-update
```
This command fetches and installs the latest version of the ruleset into the default directory (/var/lib/suricata/rules/).

### Configuration of Suricata:
Open the Suricata configuration file for editing:
```bash
sudo nano /etc/suricata/suricata.yaml
```

Key Configurations:
- **home-net:** Replace this with your actual internal network subnet.
- **rule-files:** This section specifies the location of Suricata rule files. The default rules can be found in (etc/suricata/rules/). Define your own rules and add the path in this section.

### Starting Suricata with Custom Configurations:
Commence Suricata with specific settings using the command:
```bash
sudo suricata -c suricata.yaml -s rulespath -i interface
```

Explanation:
- **Starts Suricata:** The suricata command initializes the Suricata program.
- **Configuration file:** -c suricata.yaml specifies the configuration file containing settings such as network interfaces and rule paths.
- **Rule file:** -s rulespath defines the rules file, which could be either the default rules file (/var/lib/suricata/rules/suricata.rules) or a custom one.
- **Network interface:** -i interface indicates the network interface from which Suricata will capture traffic for analysis.

### Testing and Verifying Suricata:
Monitor the activity of Suricata using the command:
```bash
sudo tail -f /var/log/suricata/fast.log
```

---

# Understanding the Basics of Suricata Rule Writing
Suricata relies on rules to identify suspicious network activity. Crafting effective rules necessitates comprehension of their structure and components. Here's an in-depth analysis:

Structure:

A Suricata rule comprises three primary sections:

- **Action:** Dictates the response upon a rule match, such as logging, alerting, or packet dropping.
- **Header:** Specifies conditions for triggering the rule, encompassing parameters like protocol, IP addresses, ports, and traffic flow direction.
- **Rule Options:** Further refine the rule's behavior utilizing options like content matching, payload analysis, and timeouts.

### 1. Action:

- alert: Logs the event with a specific severity level (e.g., low, medium, high).
- log: Logs the event without assigning a severity level.
- drop: Blocks the offending packet.
- chain: Initiates another rule for further analysis.

Example:

```bash
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Potential web server exploit attempt"; flow:to_server; classtype:attack-analysis;)
```

### 2. Header:

- protocol: Specifies the network protocol (e.g., tcp, udp, icmp).
- source/destination: Defines IP addresses or networks using CIDR notation or keywords like $HOME_NET.
- source_port/destination_port: Specifies port or port range.
- direction: Determines traffic flow direction (e.g., -> for forward, <-> for bi-directional).

### 3. Rule Options:

- msg: Specifies a custom message to be logged when the rule triggers.
- flow: Defines traffic flow direction within the rule (e.g., to_server, from_server).
- classtype: Assigns a classification category to the detected event.teps (compatible with Kali Linux):

### Installation of Suricata:

Execute the following command to install Suricata:
```bash
sudo apt-get install suricata
```

### Updating the Emerging Threats Open Ruleset:
Run the command below to update the ruleset:
```bash
sudo suricata-update
```
This command fetches and installs the latest version of the ruleset into the default directory (/var/lib/suricata/rules/).

### Configuration of Suricata:
Open the Suricata configuration file for editing:
```bash
sudo nano /etc/suricata/suricata.yaml
```

Key Configurations:
- **home-net:** Replace this with your actual internal network subnet.
- **rule-files:** This section specifies the location of Suricata rule files. The default rules can be found in (etc/suricata/rules/). Define your own rules and add the path in this section.

### Starting Suricata with Custom Configurations:
Commence Suricata with specific settings using the command:
```bash
sudo suricata -c suricata.yaml -s rulespath -i interface
```

Explanation:
- **Starts Suricata:** The suricata command initializes the Suricata program.
- **Configuration file:** -c suricata.yaml specifies the configuration file containing settings such as network interfaces and rule paths.
- **Rule file:** -s rulespath defines the rules file, which could be either the default rules file (/var/lib/suricata/rules/suricata.rules) or a custom one.
- **Network interface:** -i interface indicates the network interface from which Suricata will capture traffic for analysis.

### Testing and Verifying Suricata:
Monitor the activity of Suricata using the command:
```bash
sudo tail -f /var/log/suricata/fast.log
```

---

# Understanding the Basics of Suricata Rule Writing
Suricata relies on rules to identify suspicious network activity. Crafting effective rules necessitates comprehension of their structure and components. Here's an in-depth analysis:

Structure:

A Suricata rule comprises three primary sections:

- **Action:** Dictates the response upon a rule match, such as logging, alerting, or packet dropping.
- **Header:** Specifies conditions for triggering the rule, encompassing parameters like protocol, IP addresses, ports, and traffic flow direction.
- **Rule Options:** Further refine the rule's behavior utilizing options like content matching, payload analysis, and timeouts.

### 1. Action:

- alert: Logs the event with a specific severity level (e.g., low, medium, high).
- log: Logs the event without assigning a severity level.
- drop: Blocks the offending packet.
- chain: Initiates another rule for further analysis.

Example:

```bash
alert tcp $HOME_NET any -> $EXTERNAL_NET any (msg:"Potential web server exploit attempt"; flow:to_server; classtype:attack-analysis;)
```

### 2. Header:

- protocol: Specifies the network protocol (e.g., tcp, udp, icmp).
- source/destination: Defines IP addresses or networks using CIDR notation or keywords like $HOME_NET.
- source_port/destination_port: Specifies port or port range.
- direction: Determines traffic flow direction (e.g., -> for forward, <-> for bi-directional).

### 3. Rule Options:

- msg: Specifies a custom message to be logged when the rule triggers.
- flow: Defines traffic flow direction within the rule (e.g., to_server, from_server).
- classtype: Assigns a classification category to the detected event.
