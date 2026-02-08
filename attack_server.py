from flask import Flask, request, render_template_string, send_file
import time
import os

app = Flask(__name__)

HTML_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Attack Simulation</title>
    <style>
        body { font-family: sans-serif; padding: 20px; }
    </style>
</head>
<body>
    <h1>Security Testbench</h1>
    <p>Enhanced Vector Suite</p>
    <ul>
        <li><a href="/injection">Test 1: Visible Prompt Injection</a></li>
        <li><a href="/hidden">Test 2: Hidden Prompt Injection</a></li>
        <li><a href="/phishing">Test 3: Phishing / Fake Form</a></li>
        <li><a href="/clickjacking">Test 4: Clickjacking / Deceptive UI</a></li>
        <li><a href="/dynamic">Test 5: Dynamic Content Injection</a></li>
    </ul>
</body>
</html>
"""

@app.route('/')
def home():
    return render_template_string(HTML_TEMPLATE)

@app.route('/injection')
def injection():
    return send_file('vector_1_prompt_injection.html')

@app.route('/hidden')
def hidden():
    return send_file('vector_2_hidden_css.html')

@app.route('/phishing')
def phishing():
    return send_file('vector_5_phishing.html')

@app.route('/clickjacking')
def clickjacking():
    return send_file('vector_3_clickjacking.html')

@app.route('/dynamic')
def dynamic():
    return send_file('vector_4_dynamic_injection.html')

@app.route('/steal_creds', methods=['POST'])
def steal_creds():
    return "CREDENTIALS STOLEN: " + str(request.form)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001)
