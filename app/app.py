import os
from flask import Flask, render_template, send_from_directory, request, url_for, jsonify, abort
import stem.control

app = Flask(__name__)

app.config['DEBUG'] = False
app.config['TESTING'] = False

# Remove default error handler to prevent stack traces
@app.errorhandler(500)
def internal_error(error):
    return "Internal Server Error", 500

@app.errorhandler(404)
def not_found(error):
    return "Not Found", 404

@app.route('/content')
def content():
    return "This is the content served by the Tor hidden service."

@app.route('/')
def index():
    return render_template("index.html")

@app.route('/auto-refresh')
def auto_refresh():
    return render_template('page.html', refresh_interval=30)

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000)
