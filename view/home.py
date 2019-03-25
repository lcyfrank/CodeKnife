import webbrowser
from flask import Flask, render_template, request

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload_file():
    print(request.files)
    return 'OK'

if __name__ == '__main__':
    webbrowser.open('http://127.0.0.1:5000/')
    app.run()
