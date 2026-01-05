from flask import Flask, request
import requests
import yaml

app = Flask(__name__)

@app.route('/search')
def search():
    # XSS - Reflected
    query = request.args.get('q')
    return f"<h1>Results for: {query}</h1>"

@app.route('/fetch')
def fetch_url():
    # SSRF vulnerability
    url = request.args.get('url')
    response = requests.get(url)
    return response.text

@app.route('/config')
def load_config():
    # Unsafe YAML loading
    data = request.data
    config = yaml.load(data)  # Dangerous!
    return str(config)