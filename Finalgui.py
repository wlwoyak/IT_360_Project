import re
import dns.resolver
import tkinter as tk
from tkinter import scrolledtext, messagebox
from email import message_from_string


# Function to extract sender email, taking pythons email module and parse it to a message structure. Additional pieces are extracting different parts of the email
def extract_sender_email(email_data):
    msg = message_from_string(email_data)
    sender = msg.get("From", "")


    if sender:
        email_match = re.search(r'[\w\.-]+@[\w\.-]+', sender)
        if email_match:
            return email_match.group(0)


    return "Unknown Sender"


# Function to extract sender domain
def extract_domain(email_address):
    return email_address.split("@")[-1] if "@" in email_address else "Unknown Domain"


# Function to extract relay server IPs from "Received" headers, look at the route the ip took, and using the \d to match the ipv4 header
def extract_ips(received_headers):
    ips = []
    for header in received_headers:
        ip_match = re.search(r'(\d+\.\d+\.\d+\.\d+)', header)
        if ip_match:
            ips.append(ip_match.group(1))
    return ips if ips else ["No IPs Found"]
# Function to parse email headers
def parse_email_header(email_data):
    msg = message_from_string(email_data)
    headers = msg.items()
    return [value for key, value in headers if key.lower() == "received"]


# Function to check SPF validation, generates into text records, spf1 is start of SPF validation, had to look up this chunk of code online cause it wasn’t the easiest
def check_spf(sender_domain, sending_ip):
    try:
        result = dns.resolver.resolve(sender_domain, "TXT")
        for txt_record in result:
            if "v=spf1" in txt_record.to_text():
                if sending_ip in txt_record.to_text():
                    return True  # IP is authorized
    except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
        return False  # No SPF record found
    return False  # IP not found in SPF record
# Function to generate the final report, had to debug this one and had Chat add the symbols for final outcomes so the GUI looked a bit updated
def generate_report(email_data):
    sender_email = extract_sender_email(email_data)
    sender_domain = extract_domain(sender_email)
    received_headers = parse_email_header(email_data)
    ips = extract_ips(received_headers)


    report = f" Email Header Analysis Report for {sender_email}\n"
    report += "=" * 60 + "\n"
    report += f" Sender Domain: {sender_domain}\n"
    report += " Sender IPs and Relay Servers:\n"
   
    for ip in ips:
        report += f"   - {ip}\n"


    if sender_domain != "Unknown Domain" and ips[0] != "No IPs Found":
        spf_check = check_spf(sender_domain, ips[0])  
# Check first IP against SPF
        report += "\n🔎 Potential Spoofing: " + ("✅ No issues found." if spf_check else "⚠️ SPF check failed, possible spoofing.")
    else:
        report += "\n🔎 Potential Spoofing: ❌ Unable to verify."


    return report


# Function triggered when "Analyze" button is clicked
def analyze_email():
    email_header = input_text.get("1.0", tk.END).strip()
   
    if not email_header:
        messagebox.showerror("Error", "Please enter an email header for analysis.")
        return
    report = generate_report(email_header)
    output_text.config(state=tk.NORMAL)  # Enable editing
    output_text.delete("1.0", tk.END)  # Clear previous text
    output_text.insert(tk.END, report)  # Insert new report
    output_text.config(state=tk.DISABLED)  # Disable editing


# Creates the GUI window
root = tk.Tk()
root.title("Email Header Analyzer")
root.geometry("700x500")
root.resizable(False, False)


# Header Input Label
tk.Label(root, text="Paste Email Header Below:", font=("Arial", 12)).pack(pady=5)


# Scrollable Text Box for Email Header Input, used inside gui pop up
input_text = scrolledtext.ScrolledText(root, height=10, width=80, wrap=tk.WORD)
input_text.pack(padx=10, pady=5)


# Analyze Button, used in the gui and is just the design
analyze_button = tk.Button(root, text="Analyze Email Header", font=("Arial", 12), command=analyze_email)
analyze_button.pack(pady=10)
# Output Label
tk.Label(root, text="Analysis Report:", font=("Arial", 12)).pack(pady=5)


# Scrollable Text Box for Output, used in the gui
output_text = scrolledtext.ScrolledText(root, height=10, width=80, wrap=tk.WORD, state=tk.DISABLED)
output_text.pack(padx=10, pady=5)
# Run the GUI loop
root.mainloop()
