\# MISP MCP Server



This project provides a \*\*Model Context Protocol (MCP)\*\* server that connects to a local or remote \[MISP](https://www.misp-project.org/) (Malware Information Sharing Platform) instance.  

It enables automation and integration with your MCP-compatible agents for tasks like searching events, creating new events, and adding attributes.



---



\## ✨ Features

\- \*\*Ping MISP\*\* → Check connectivity and get version.  

\- \*\*Search Events\*\* → Find events by value (IP, domain, hash, etc.).  

\- \*\*Create Event\*\* → Add new MISP events programmatically.  

\- \*\*Add Attribute\*\* → Add indicators (IOCs) to existing events.  

\- Loads \*\*sensitive configuration from `.env`\*\* (URL, API key, TLS verify).  



---



\## 📦 Requirements

\- Python 3.9+

\- \[MISP](https://www.misp-project.org/) running locally or remotely.

\- API key for your MISP user account.



---



\## 🔧 Installation



Clone this repo and install dependencies:



```bash

pip install pymisp python-dotenv



