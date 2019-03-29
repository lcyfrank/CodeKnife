import webbrowser
from flask import Flask, render_template, request, redirect, url_for
import os
import zipfile
from basic_analysis import basic_analysis

ALLOWED_EXTENSIONS = {'app', 'ipa'}
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'upload'


_g_file_path = None


def filter_file_type(file_name: str):
    if '.' in file_name and file_name.split('.')[1].lower() in ALLOWED_EXTENSIONS:
        return True
    return False


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/analysis')
def analysis():
    global _g_file_path
    if _g_file_path is not None:
        basic_info = basic_analysis(_g_file_path)
        _g_file_path = None
        print(basic_info)
    return render_template('analysis.html')


def extract_from_zip(path):
    zip_file = zipfile.ZipFile(path)
    target_name = zip_file.namelist()[0][:-1]
    zip_file.extractall(app.config['UPLOAD_FOLDER'])
    return os.path.join(app.config['UPLOAD_FOLDER'], target_name)


@app.route('/upload', methods=['POST'])
def upload_file():
    global _g_file_path
    if 'file' in request.files:
        file = request.files['file']
        file_name = file.filename
        if filter_file_type(file_name):
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_name)
            file.save(file_path)
            if file_name.split('.')[-1] == 'zip':
                app_path = extract_from_zip(file_path)
            else:
                app_path = file_path
            _g_file_path = app_path
            return 'OK'
    return 'Error'


if __name__ == '__main__':
    webbrowser.open('http://127.0.0.1:5000/')
    app.run()
