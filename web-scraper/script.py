import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime as dt
import asyncio
import aiohttp
import re
from bs4 import BeautifulSoup
from urllib.parse import quote
import csv

def send_email(sender_email, sender_password, recipient_email, subject, body):
    # Create the email
    msg = MIMEMultipart()
    msg['From'] = sender_email
    msg['To'] = recipient_email
    msg['Subject'] = subject
    msg.attach(MIMEText(body, 'plain'))

    try:
        server = smtplib.SMTP('smtp.gmail.com', 587)  # For Gmail
        server.starttls()  # Upgrade the connection to a secure encrypted SSL/TLS connection
        server.login(sender_email, sender_password)  # Log in to your email account
        server.send_message(msg)
        print("Email sent successfully!")
    except Exception as e:
        print(f"Failed to send email: {e}")
    finally:
        server.quit()  # Close the SMTP server connection

async def fetch(session, url):
    try:
        async with session.get(url) as response:
            if response.status == 200:
                return await response.text()
            else:
                print(f"Error received: {response.status} for URL: {url}")
                return None
    except aiohttp.ClientError as e:
        print(f"Client error for URL {url}: {e}")
        return None
    except Exception as e:
        print(f"Unexpected error for URL {url}: {e}")
        return None

async def fetch_cve_details(session, cve_id, csv_file, fieldnames):
    url1 = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
    cve_detail_html = await fetch(session, url1)

    if cve_detail_html:
        soup1 = BeautifulSoup(cve_detail_html, 'html.parser')
        try:
            source_element = soup1.find('span', {'data-testid': 'vuln-current-description-source'})
            source = source_element.get_text(strip=True) if source_element else "N/A"

            description_element = soup1.find('p', {'data-testid': 'vuln-description'})
            description = description_element.get_text(strip=True) if description_element else "N/A"

            # Extract severity score and level
            severity_element = soup1.find('a', {'data-testid': 'vuln-cvss3-cna-panel-score'})
            severity_level = ""
            severity = ""
            if severity_element:
                severity_vuln = severity_element.get_text(strip=True)
                match = re.match(r"(\d+\.\d+)\s+(\w+)", severity_vuln)
                # severity = ""
                if match:
                    severity_score = match.group(1)
                    severity_level = match.group(2)
                    severity = f"{severity_score} {severity_level}"

            publish_element = soup1.find('span', {'data-testid': 'vuln-published-on'})
            published = publish_element.get_text(strip=True) if publish_element else "N/A"

            patch_element = soup1.find('td', {'data-testid': 'vuln-hyperlinks-link-0'})
            patch = patch_element.find('a')['href'] if patch_element and patch_element.find('a') else "N/A"
            # print(patch)

            # Write to CSV
            if severity_level in ['High','Critical']:
               with open(csv_file, 'a', newline='') as file:
                writer = csv.DictWriter(file, fieldnames=fieldnames)
                writer.writerow({
                    'Unique ID': cve_id,
                    'Product Name': source,
                    'Description': description,
                    'Severity level': severity,
                    'Published Date': published
                })
                
        except Exception as e:
            print(f"Error extracting details for {cve_id}: {e}")

async def main():
    date = dt.now().strftime("%m/%d/%Y")
    month, day, year = date.split('/')
    formatted_month = quote(month)
    formatted_day = quote(day)
    formatted_year = year
    url = f'https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&pub_start_date={formatted_month}%2F{formatted_day}%2F{formatted_year}&pub_end_date={formatted_month}%2F{formatted_day}%2F{formatted_year}'
    #url = f'https://nvd.nist.gov/vuln/search/results?form_type=Advanced&results_type=overview&search_type=all&isCpeNameSearch=false&pub_start_date=08%2F21%2F2024&pub_end_date=08%2F22%2F2024'
    csv_file = 'cve_data.csv'
    fieldnames = ['Unique ID','Product Name', 'OEM Name','Description','Security Score', 'Severity Level','Published Date'] 
    new_vul = []
    # Check if the file exists, if not, write the header row
    cve_ids_in_file = set()
    try:
        with open(csv_file, 'r') as file:
            reader = csv.DictReader(file)
            cve_ids_in_file = {row['Unique ID'] for row in reader}
            
    except FileNotFoundError:
        with open(csv_file, 'w', newline='') as file:
            writer = csv.DictWriter(file, fieldnames=fieldnames)
            writer.writeheader()
            cve_ids_in_file=set()

    async with aiohttp.ClientSession() as session:
        # Fetch the main page
        main_page_html = await fetch(session, url)
        if main_page_html:
            soup = BeautifulSoup(main_page_html, 'html.parser')
            cve_elements = soup.find_all('a', href=re.compile(r'/vuln/detail/CVE-\d{4}-\d+'))
            cve_ids = [cve.get_text(strip=True) for cve in cve_elements]

            for cve_id in cve_ids:

                if cve_id in cve_ids_in_file:
                    continue

                url1 = f"https://nvd.nist.gov/vuln/detail/{cve_id}"
                cve_detail_html = await fetch(session, url1)

                if cve_detail_html:
                    soup1 = BeautifulSoup(cve_detail_html, 'html.parser')
                    # Extracting description, severity, publish date, source
                    try:
                        source_element = soup1.find('span', {'data-testid': 'vuln-current-description-source'})
                        source = source_element.get_text(strip=True)

                        description_element = soup1.find('p', {'data-testid': 'vuln-description'})
                        description = description_element.get_text(strip=True)

                        # severity = ""
                        severity_element = soup1.find('a', {'data-testid': 'vuln-cvss3-cna-panel-score'})
                        severity_vuln = severity_element
                        severity_score = None
                        severity_level = ""
                        try:
                         if severity_element:
                            severity_vuln = severity_element.get_text(strip=True)
                            match = re.match(r"(\d+\.\d+)\s+(\w+)", severity_vuln)
                            if match:
                                severity_score = match.group(1)
                                severity_level = match.group(2)
                                # severity = f"{severity_score} {severity_level}"
                        except:
                            print("N/A")
                        
                        publish_element = soup1.find('span', {'data-testid': 'vuln-published-on'})
                        published = publish_element.get_text(strip=True) if publish_element else "N/A"
                        # Write to CSV
                        with open(csv_file, 'a', newline='') as file:
                            writer = csv.DictWriter(file, fieldnames=fieldnames)
                            writer.writerow({ 
                                    'Unique ID': cve_id,
                                    'Product Name': source,
                                    'OEM Name':source,
                                    'Description': description,
                                    'Security Score':severity_score,
                                    'Severity Level': severity_level,
                                    'Published Date': published
                            })
                        new_vul.append(f"{cve_id}:{source}\nDescription :{description} \nSecurity_score: {severity_score} \nSeverity_level: {severity_level} \nPublished: {published} \n\n")
                    except AttributeError as e:
                        print("Error extracting description:", e)
        if new_vul:
            sender_email = "YOUR_EMAIL"
            sender_password =  "YOUR_APP_PASSWORD"   # Use an app password
            recipient_email = "YOUR_EMAIL"
            subject = "Newly Found Vulnerability Information"
            body = "\n".join(new_vul)

            send_email(sender_email, sender_password, recipient_email, subject, body)
        else: pass
    # Send email with vulnerability information
  
# Run the main function
asyncio.run(main())
