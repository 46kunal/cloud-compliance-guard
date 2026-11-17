"""CERT-In Annexure I incident types and reporting contacts (CERT-In Directions No. 20(3)/2022-CERT-In, 28 April 2022).

Read from the official PDF on 17 November 2026. Reporting must happen within 6 hours of noticing an incident
(Direction (ii)). The contacts below are the ones printed in the direction; CERT-In also publishes its own
reporting form and may update the details, so check cert-in.org.in before filing.
"""

ANNEXURE_I = [
    ("i", "Targeted scanning/probing of critical networks/systems"),
    ("ii", "Compromise of critical systems/information"),
    ("iii", "Unauthorised access of IT systems/data"),
    ("iv", "Defacement of website or intrusion into a website and unauthorised changes such as inserting malicious code, links to external websites etc."),
    ("v", "Malicious code attacks such as spreading of virus/worm/Trojan/Bots/Spyware/Ransomware/Cryptominers"),
    ("vi", "Attack on servers such as Database, Mail and DNS and network devices such as Routers"),
    ("vii", "Identity Theft, spoofing and phishing attacks"),
    ("viii", "Denial of Service (DoS) and Distributed Denial of Service (DDoS) attacks"),
    ("ix", "Attacks on Critical infrastructure, SCADA and operational technology systems and Wireless networks"),
    ("x", "Attacks on Application such as E-Governance, E-Commerce etc."),
    ("xi", "Data Breach"),
    ("xii", "Data Leak"),
    ("xiii", "Attacks on Internet of Things (IoT) devices and associated systems, networks, software, servers"),
    ("xiv", "Attacks or incident affecting Digital Payment systems"),
    ("xv", "Attacks through Malicious mobile Apps"),
    ("xvi", "Fake mobile Apps"),
    ("xvii", "Unauthorised access to social media accounts"),
    ("xviii", "Attacks or malicious/suspicious activities affecting Cloud computing systems/servers/software/applications"),
    ("xix", "Attacks or malicious/suspicious activities affecting systems/servers/networks/software/applications related to Big Data, Block chain, virtual assets, virtual asset exchanges, custodian wallets, Robotics, 3D and 4D Printing, additive manufacturing, Drones"),
    ("xx", "Attacks or malicious/suspicious activities affecting systems/servers/software/applications related to Artificial Intelligence and Machine Learning"),
]

CERTIN_CONTACT = {"email": "incident@cert-in.org.in", "phone": "1800-11-4949", "fax": "1800-11-6969",
                  "website": "www.cert-in.org.in"}

TYPE_IDS = {item_id for item_id, _ in ANNEXURE_I}
TYPE_TEXT = dict(ANNEXURE_I)
