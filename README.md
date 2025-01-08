
# **AI-Powered Reconnaissance Tool**

### **Project Overview**
This project implements a **reconnaissance bot** designed to collect and analyze various public information about a domain or IP address. It integrates several open-source tools and APIs to gather data from different sources, such as **WHOIS databases**, **port scanning**, **subdomain enumeration**, **security services**, and **reconnaissance APIs**. The collected data is then processed and summarized using OpenAI's **GPT-3.5** model, making it an advanced, intelligent tool for domain intelligence gathering.

The tool serves security researchers, penetration testers, and anyone involved in cybersecurity and reconnaissance by automating the collection of crucial information about a target, which can be leveraged for vulnerability analysis, threat modeling, or general security auditing.

### **Features and Components**

#### **1. WHOIS Lookup**
The bot performs a **WHOIS lookup** to retrieve public registration data about a domain, such as the owner’s name, contact details, registration dates, and domain history. This information helps identify domain ownership and track possible domain history changes.

#### **2. Nmap Port Scanning**
Using **Nmap**, the bot performs an initial scan on the domain or IP address to identify open ports (ports 1–1024) on the target machine. This helps security analysts quickly identify which services might be running on a target system and spot potential vulnerabilities that could be exploited.

#### **3. Subdomain & Email Enumeration via TheHarvester**
**TheHarvester** is used to gather subdomains, emails, and other domain-related data. By querying multiple search engines and public sources, it provides valuable insights into a domain's structure, including possible entry points for attackers to exploit. The **subdomains** can reveal hidden services or applications that may not be immediately visible through normal web browsing.

#### **4. Censys API Integration**
The bot integrates the **Censys API** to pull data on devices and services associated with a target domain. Censys scans the internet to index exposed services and devices, providing insights into the technologies in use on a given domain, their configurations, and potential misconfigurations that may be vulnerable.

#### **5. Spyse API Integration**
By integrating the **Spyse API**, the bot can perform in-depth analysis on the target's infrastructure, including IPs, networks, and other related data. Spyse's powerful reconnaissance engine allows the bot to gather intelligence about assets, systems, and services related to a target, which is particularly useful for identifying security risks.

#### **6. SecurityTrails API Integration**
Using the **SecurityTrails API**, the tool retrieves comprehensive historical domain data, DNS records, and IP information. This helps to understand the evolution of a domain and identify any security concerns related to its infrastructure.

#### **7. Summarizing with OpenAI**
All the collected information is then sent to OpenAI's **GPT-3.5** (or GPT-4) model for summarization. The model condenses the raw data into a concise and understandable format, presenting actionable insights. This allows users to quickly analyze large amounts of reconnaissance data without having to sift through raw output manually.

---

### **How It Works**

1. **Input:** The user provides a domain name or IP address to the reconnaissance bot.
2. **Reconnaissance Process:** The bot collects data from multiple sources, including:
   - WHOIS data
   - Port scan results from Nmap
   - Subdomains and emails using TheHarvester
   - Data from the Censys, Spyse, and SecurityTrails APIs
3. **Data Processing:** The bot processes and organizes the data.
4. **Summarization:** The gathered data is summarized using OpenAI's GPT model.
5. **Output:** The user receives a comprehensive, easy-to-read summary of the findings.

---

### **Installation**

To use this tool, follow these steps:

1. **Clone the repository** to your local machine:
    ```bash
    git clone https://github.com/your-username/recon-bot.git
    ```

2. **Install dependencies** using `pip`:
    ```bash
    pip install -r requirements.txt
    ```

3. **Configure API Keys**: Set your API keys for OpenAI, Censys, Spyse, and SecurityTrails in the `recon_bot.py` file.
    - **OpenAI**: [Sign up for OpenAI API](https://platform.openai.com/signup)
    - **Censys**: [Sign up for Censys API](https://censys.io/)
    - **Spyse**: [Sign up for Spyse API](https://spyse.com/)
    - **SecurityTrails**: [Sign up for SecurityTrails API](https://securitytrails.com/)

4. **Run the reconnaissance bot** by executing:
    ```bash
    python recon_bot.py
    ```

---

### **Usage Example**

To start a reconnaissance scan, simply run the script and enter a domain when prompted:

```bash
Enter a domain to recon: example.com
```

The bot will then proceed to gather information, scan ports, and generate a summarized report.

---

### **Project Structure**

- `recon_bot.py`: Main script that contains the logic for performing reconnaissance and summarizing the results.
- `requirements.txt`: List of dependencies required for the project, such as `requests`, `openai`, `nmap`, `theHarvester`, etc.
- `README.md`: Documentation for setup, usage, and configuration.
  
---

### **Why This Tool Is Useful**

- **Automated Reconnaissance:** This tool automates the process of gathering crucial data from a variety of sources, significantly reducing the time and effort required for manual reconnaissance.
- **Open Source and Free to Use:** This tool is built with open-source and free APIs, making it accessible to anyone who needs it.
- **Comprehensive Intelligence Gathering:** By combining data from multiple sources, the tool provides a holistic view of a target's infrastructure and online presence.
- **Summarized Insights:** Instead of dealing with raw data, users get a concise summary that makes it easier to spot vulnerabilities or areas of concern.

---

### **Contributing**

We welcome contributions! If you would like to contribute to this project, please fork the repository, make your changes, and submit a pull request. 

Please follow the guidelines mentioned in the [CONTRIBUTING.md](CONTRIBUTING.md) file for best practices and submission instructions.

---

### **License**

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

### **Acknowledgments**
- **OpenAI**: For providing the powerful GPT-3.5/4 model for summarizing reconnaissance results.
- **Censys**: For offering public security data about exposed services and devices.
- **Spyse**: For enabling in-depth security reconnaissance.
- **TheHarvester**: For providing subdomain enumeration and email harvesting.
- **SecurityTrails**: For domain intelligence and historical data.

---

This project aims to provide an automated, all-in-one reconnaissance tool, helping security professionals and researchers quickly gather domain intelligence and identify security risks.
