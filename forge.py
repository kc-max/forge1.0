import requests 
from flask import Flask, render_template_string, request, send_file, url_for, redirect
import concurrent.futures
from selenium import webdriver
from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
from PIL import Image
import os
import pandas as pd
from io import BytesIO
from datetime import datetime
import re
import threading
import time

app = Flask(__name__)

# Global list to store search history
search_history = []

# Global dictionary to store monitoring status and new subdomains for each domain
monitoring_status = {}
new_subdomains_dict = {}

def validate_domain(domain):
    # Simple regex to validate domain names
    pattern = re.compile(r'^(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$')
    return pattern.match(domain)

def chaos_subdomains(domain):
    subdomains = []
    
    # Use Project Discovery Chaos API to get subdomains
    api_key = '3e5ddbe7-f000-4c4c-bd3a-03fc6f27505b'
    headers = {
        'Authorization': f'Bearer {api_key}'
    }
    response = requests.get(f"https://dns.projectdiscovery.io/dns/{domain}/subdomains", headers=headers)
    
    if response.status_code == 200:
        subs = response.json().get('subdomains', [])
        subdomains.extend(subs)
    else:
        print(f"Failed to fetch subdomains: {response.status_code} - {response.text}")
    
    return subdomains

def shodan_subdomains(domain):
    subdomains = []
    
    # Use Shodan API to get subdomains
    api_key = 'C5oagsQMMHwRw3xWF669DjutpTdH6WYv'
    
    response = requests.get(f"https://api.shodan.io/dns/domain/{domain}?key={api_key}")

    if response.status_code == 200:
        subs = response.json().get('data', [])
        subdomains.extend([sub['subdomain'] for sub in subs])
    else:
        print(f"Failed to fetch subdomains: {response.status_code} - {response.text}")

    return subdomains

def crtsh_subdomains(domain):
    subdomains = []
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    response = requests.get(url)
    
    if response.status_code == 200:
        certs = response.json()
        for cert in certs:
            name_value = cert.get('name_value')
            if name_value:
                subdomains.extend(name_value.split('\n'))
    
    return list(set(subdomains))  # Remove duplicates

def get_combined_subdomains(domain, use_chaos, use_shodan, use_crtsh):
    subdomains = []
    with concurrent.futures.ThreadPoolExecutor() as executor:
        futures = []
        if use_chaos:
            futures.append(executor.submit(chaos_subdomains, domain))
        if use_shodan:
            futures.append(executor.submit(shodan_subdomains, domain))
        if use_crtsh:
            futures.append(executor.submit(crtsh_subdomains, domain))
        
        results = [future.result() for future in concurrent.futures.as_completed(futures)]
        for result in results:
            subdomains.extend(result)
    
    combined_subs = list(set(subdomains))  # Combine and remove duplicates
    return combined_subs

def get_status_code(full_subdomain):
    try:
        response = requests.get(f"http://{full_subdomain}", timeout=5)
        return response.status_code
    except requests.RequestException:
        return None

def capture_screenshot(driver, url, filename):
    driver.get(url)
    driver.save_screenshot(filename)
    # Resize the image
    image = Image.open(filename)
    image = image.resize((150, 100), Image.ANTIALIAS)
    image.save(filename)

def monitor_new_subdomains():
    while True:
        for domain, status in monitoring_status.items():
            if status:
                use_chaos = True
                use_shodan = True
                use_crtsh = True
                new_subdomains = get_combined_subdomains(domain, use_chaos, use_shodan, use_crtsh)
                new_full_subdomains = [f"{sub}.{domain}" for sub in new_subdomains]
                
                # Check for new subdomains
                existing_subdomains = set(search_history[domain]['subdomain_statuses'].keys())
                new_found_subdomains = set(new_full_subdomains) - existing_subdomains
                
                if new_found_subdomains:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                        future_to_subdomain = {executor.submit(get_status_code, sub): sub for sub in new_found_subdomains}
                        new_subdomain_statuses = {future_to_subdomain[future]: future.result() for future in concurrent.futures.as_completed(future_to_subdomain)}
                    
                    search_history[domain]['subdomain_statuses'].update(new_subdomain_statuses)
                    search_history[domain]['num_subdomains'] = len(search_history[domain]['subdomain_statuses'])
                    
                    if search_history[domain]['screenshots']:
                        options = Options()
                        options.headless = True
                        driver = webdriver.Chrome(service=ChromeService(ChromeDriverManager().install()), options=options)
                        domain_dir = f'static/screenshots/{domain}'
                        os.makedirs(domain_dir, exist_ok=True)
                        
                        with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
                            for sub in new_found_subdomains:
                                filename = f'{domain_dir}/{sub}.png'
                                executor.submit(capture_screenshot, driver, f"http://{sub}", filename)
                                search_history[domain]['screenshots'][sub] = filename
                        
                        driver.quit()
                    
                    # Add new subdomains to the global new_subdomains_dict
                    if domain not in new_subdomains_dict:
                        new_subdomains_dict[domain] = []
                    new_subdomains_dict[domain].extend(new_found_subdomains)
        
        time.sleep(3600)  # Check for new subdomains every hour

@app.route('/subnames', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        domain = request.form.get('domain')
        if not validate_domain(domain):
            return "Invalid domain name", 400
        
        use_chaos = 'chaos' in request.form
        use_shodan = 'shodan' in request.form
        use_crtsh = 'crtsh' in request.form
        capture_screenshots = 'screenshots' in request.form
        save_csv = 'save_csv' in request.form
        
        subdomains = get_combined_subdomains(domain, use_chaos, use_shodan, use_crtsh)
        full_subdomains = [f"{sub}.{domain}" for sub in subdomains]
        
        with concurrent.futures.ThreadPoolExecutor() as executor:
            future_to_subdomain = {executor.submit(get_status_code, sub): sub for sub in full_subdomains}
            subdomain_statuses = {future_to_subdomain[future]: future.result() for future in concurrent.futures.as_completed(future_to_subdomain)}
        
        num_subdomains = len(full_subdomains)
        
        screenshots = {}
        if capture_screenshots:
            options = Options()
            options.headless = True
            driver = webdriver.Chrome(service=ChromeService(ChromeDriverManager().install()), options=options)
            domain_dir = f'static/screenshots/{domain}'
            os.makedirs(domain_dir, exist_ok=True)
            
            with concurrent.futures.ThreadPoolExecutor() as executor:
                for sub in full_subdomains:
                    filename = f'{domain_dir}/{sub}.png'
                    executor.submit(capture_screenshot, driver, f"http://{sub}", filename)
                    screenshots[sub] = filename
            
            driver.quit()
        
        # Save the search result to history with a timestamp
        search_history.append({
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'domain': domain,
            'subdomain_statuses': subdomain_statuses,
            'screenshots': screenshots,
            'num_subdomains': num_subdomains
        })

        if save_csv:
            df = pd.DataFrame(list(subdomain_statuses.items()), columns=['Subdomain', 'Status'])
            csv_filename = f'{domain}_subdomains.csv'
            csv_buffer = BytesIO()
            df.to_csv(csv_buffer, index=False)
            csv_buffer.seek(0)
            return send_file(csv_buffer, as_attachment=True, download_name=csv_filename, mimetype='text/csv')
        
        return render_template_string('''
            <form method="post">
                Domain: <input type="text" name="domain"><br>
                <input type="checkbox" name="chaos" value="chaos"> Use Chaos<br>
                <input type="checkbox" name="shodan" value="shodan"> Use Shodan<br>
                <input type="checkbox" name="crtsh" value="crtsh"> Use crt.sh<br>
                <input type="checkbox" name="screenshots" value="screenshots"> Capture Screenshots<br>
                <input type="checkbox" name="save_csv" value="save_csv"> Save to CSV<br>
                <input type="submit" value="Submit">
            </form>
            <p>Number of subdomains: {{ num_subdomains }}</p>
            <h2>Subdomains:</h2>
            <ul>
                {% for sub, status in subdomain_statuses.items() %}
                    <li>{{ sub }} - {{ status }}
                    {% if screenshots %}
                        <br><img src="{{ url_for('static', filename='screenshots/' + domain + '/' + sub + '.png') }}" alt="Screenshot of {{ sub }}">
                    {% endif %}
                    </li>
                {% endfor %}
            </ul>
            {% if save_csv %}
                <p><a href="{{ url_for('static', filename=domain + '_subdomains.csv') }}">Download CSV</a></p>
            {% endif %}
        ''', subdomain_statuses=subdomain_statuses, num_subdomains=num_subdomains, domain=domain, screenshots=screenshots, save_csv=save_csv)
    return '''
        <form method="post">
            Domain: <input type="text" name="domain"><br>
            <input type="checkbox" name="chaos" value="chaos"> Use Chaos<br>
            <input type="checkbox" name="shodan" value="shodan"> Use Shodan<br>
            <input type="checkbox" name="crtsh" value="crtsh"> Use crt.sh<br>
            <input type="checkbox" name="screenshots" value="screenshots"> Capture Screenshots<br>
            <input type="checkbox" name="save_csv" value="save_csv"> Save to CSV<br>
            <input type="submit" value="Submit">
        </form>
    '''
@app.route('/history')
def history():
    return render_template_string('''
        <h2>Search History</h2>
        <ul>
            {% for record in search_history %}
                <li>
                    <strong>Timestamp:</strong> {{ record.timestamp }}<br>
                    <strong>Domain:</strong> <a href="{{ url_for('view_record', index=loop.index0) }}">{{ record.domain }}</a><br>
                    <strong>Number of Subdomains:</strong> {{ record.num_subdomains }}<br>
                    <a href="{{ url_for('delete_record', index=loop.index0) }}">Delete</a>
                </li>
            {% endfor %}
        </ul>
        <a href="{{ url_for('index') }}">Back to Search</a>
    ''', search_history=search_history)

@app.route('/view/<int:index>')
def view_record(index):
    if 0 <= index < len(search_history):
        record = search_history[index]
        return render_template_string('''
            <h2>Search Result for {{ record.domain }}</h2>
            <p><strong>Timestamp:</strong> {{ record.timestamp }}</p>
            <p><strong>Number of Subdomains:</strong> {{ record.num_subdomains }}</p>
            <ul>
                {% for sub, status in record.subdomain_statuses.items() %}
                    <li>{{ sub }} - {{ status }}
                    {% if record.screenshots %}
                        <br><img src="{{ url_for('static', filename='screenshots/' + record.domain + '/' + sub + '.png') }}" alt="Screenshot of {{ sub }}">
                    {% endif %}
                    </li>
                {% endfor %}
            </ul>
            <a href="{{ url_for('history') }}">Back to History</a>
        ''', record=record)
    return redirect(url_for('history'))

@app.route('/delete/<int:index>')
def delete_record(index):
    if 0 <= index < len(search_history):
        # Remove the screenshots directory for the domain
        domain = search_history[index]['domain']
        domain_dir = f'static/screenshots/{domain}'
        if os.path.exists(domain_dir):
            for file in os.listdir(domain_dir):
                os.remove(os.path.join(domain_dir, file))
            os.rmdir(domain_dir)

@app.route('/start_monitoring/<domain>')
def start_monitoring(domain):
    if validate_domain(domain):
        monitoring_status[domain] = True
    return redirect(url_for('monitor'))

@app.route('/stop_monitoring/<domain>')
def stop_monitoring(domain):
    if validate_domain(domain):
        monitoring_status[domain] = False
    return redirect(url_for('monitor'))

@app.route('/delete_monitoring/<domain>')
def delete_monitoring(domain):
    if validate_domain(domain):
        monitoring_status.pop(domain, None)
        new_subdomains_dict.pop(domain, None)
    return redirect(url_for('monitor'))

@app.route('/monitor', methods=['GET', 'POST'])
def monitor():
    if request.method == 'POST':
        new_domain = request.form.get('new_domain')
        if new_domain and validate_domain(new_domain):
            monitoring_status[new_domain] = True
            new_subdomains_dict[new_domain] = []
        
        for domain in monitoring_status.keys():
            monitoring_status[domain] = request.form.get(f'monitor_{domain}') == 'on'
        return redirect(url_for('monitor'))
    
    return render_template_string('''
        <h2>New Subdomains</h2>
        <form method="post">
            <label for="new_domain">Add Domain to Monitor:</label>
            <input type="text" id="new_domain" name="new_domain">
            <input type="submit" value="Add Domain">
        </form>
        <form method="post" id="monitor_form">
            <ul>
                {% for domain, subdomains in new_subdomains_dict.items() %}
                    <li>
                        <strong>Domain:</strong> {{ domain }}<br>
                        <ul>
                            {% for subdomain in subdomains %}
                                <li>{{ subdomain }}</li>
                            {% endfor %}
                        </ul>
                        <input type="checkbox" name="monitor_{{ domain }}" {% if monitoring_status.get(domain) %}checked{% endif %} onchange="document.getElementById('monitor_form').submit()"> Monitor
                        <a href="{{ url_for('delete_monitoring', domain=domain) }}">Delete</a>
                    </li>
                {% endfor %}
            </ul>
        </form>
        <a href="{{ url_for('index') }}">Back to Search</a>
        <script>
            document.querySelectorAll('input[type="checkbox"]').forEach(function(checkbox) {
                checkbox.addEventListener('change', function() {
                    document.getElementById('monitor_form').submit();
                });
            });
        </script>
    ''', new_subdomains_dict=new_subdomains_dict, monitoring_status=monitoring_status)

if __name__ == '__main__':
    # Start the background thread to monitor for new subdomains
    threading.Thread(target=monitor_new_subdomains, daemon=True).start()

    from waitress import serve
    serve(app, host="127.0.0.1", port=3000)