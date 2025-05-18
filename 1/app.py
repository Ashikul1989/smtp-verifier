from flask import Flask, request, render_template
import re
import dns.resolver
import smtplib

app = Flask(__name__)

EMAIL_REGEX = re.compile(r"^[^@]+@[^@]+\.[^@]+$")

def check_mx(domain):
    try:
        records = dns.resolver.resolve(domain, 'MX')
        return sorted([(r.preference, str(r.exchange)) for r in records])
    except Exception:
        return None

def smtp_check(email, mx_records):
    try:
        from_address = "verify@example.com"
        for _, mx in mx_records:
            server = smtplib.SMTP(timeout=10)
            server.connect(mx)
            server.helo()
            server.mail(from_address)
            code, _ = server.rcpt(email)
            server.quit()
            return code in [250, 251]
    except:
        return False

@app.route('/', methods=['GET', 'POST'])
def index():
    results = []
    if request.method == 'POST':
        email_list = request.form['emails'].splitlines()
        for email in email_list:
            email = email.strip().lower()
            if not EMAIL_REGEX.match(email):
                results.append((email, '❌ Invalid Format'))
                continue
            domain = email.split('@')[1]
            mx = check_mx(domain)
            if not mx:
                results.append((email, '❌ No MX Record'))
                continue
            is_valid = smtp_check(email, mx)
            results.append((email, '✅ Valid' if is_valid else '❌ SMTP Failed'))
    return render_template('index.html', results=results)

if __name__ == '__main__':
    app.run(debug=True)
