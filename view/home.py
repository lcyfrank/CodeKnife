import webbrowser
from flask import Flask, render_template, request, redirect, url_for, jsonify, session
import os
import zipfile
from basic_analysis import basic_analysis
from static_analysis import view_static_analysis
import threading
from queue import Queue
from utils import md5_for_file
from models.mach_object import *
from models.macho_method_hub import *
from models.mongo_storage import *

ALLOWED_EXTENSIONS = {'app', 'ipa'}
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'upload'


_g_process_msg_queues = {}


def filter_file_type(file_name: str):
    if '.' in file_name and file_name.split('.')[1].lower() in ALLOWED_EXTENSIONS:
        return True
    return False


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/analysis/basic/<file_md5>')
def analysis(file_md5):

    file_path = load_path_of_md5(file_md5)
    basic_info = load_basic_info_of_md5(file_md5)
    if basic_info is not None:
        return render_template('analysis.html', basic_info=basic_info, md5=file_md5)
    else:
        if file_path is not None:
            basic_info = basic_analysis(file_path)
            store_md5_with_basic_info(file_md5, basic_info)
            return render_template('analysis.html', basic_info=basic_info, md5=file_md5)
    return '''
    <html>
    <head><title>Analysis</title></head>
    <body><h1>Access error!</h1></body>
    </html>
    '''


@app.route('/analysis/binary/pre_process')
def binary_process_log():
    global _g_process_msg_queues

    file_md5 = request.args.get('md5')
    if file_md5 in _g_process_msg_queues:  # 正在分析
        msg_queue = _g_process_msg_queues[file_md5]
        try:
            msg = msg_queue.get(block=False)
        except:
            msg = ''
        processing = msg != 'Analyse all methods complete' and len(msg) > 0
        if not processing:
            del _g_process_msg_queues[file_md5]
        response_dict = {
            'success': True,
            'data': {
                'processing': processing,
                'msg': msg
            }
        }
        return jsonify(response_dict)
    else:
        response_dict = {
            'success': True,
            'data': {
                'processing': False,
                'msg': ''
            }
        }
        return jsonify(response_dict)


@app.route('/analysis/binary/<file_md5>')
def binary_analysis(file_md5):
    basic_info = load_basic_info_of_md5(file_md5)
    if basic_info is not None:

        if file_md5 not in _g_process_msg_queues:  # 说明没有正在分析
            _g_process_msg_queues[file_md5] = Queue(100)

            app_name = basic_info.display_name
            app_path = os.path.join(basic_info.app_path, basic_info.execute_path)
            t = threading.Thread(target=view_static_analysis, args=(app_path, app_name, 0, _g_process_msg_queues[file_md5]))
            t.start()
            return render_template('binary.html', complete=0, md5=file_md5)
        else:  # 说明正在分析
            return render_template('binary.html', complete=1, md5=file_md5)
    else:
        return '''
        <html>
        <head><title>Analysis</title></head>
        <body><h1>Access error!</h1></body>
        </html>
        '''


    # global _g_binary_status
    # if _g_binary_status == 0:  # 没有分析
    #     _g_binary_status = 1
    #     global _g_file_path
    #     global _g_basic_info
    #     # if _g_file_path is not None:
    #     app_name = _g_basic_info.display_name
    #     app_path = os.path.join(_g_basic_info.app_path, _g_basic_info.execute_path)
    #
    #     global _g_object_queue
    #     global _g_msg_queue
    #     t = threading.Thread(target=view_static_analysis, args=(app_path, app_name, 0, _g_object_queue, _g_msg_queue))
    #     t.start()
    #     return render_template('binary.html', complete=0)
    # elif _g_binary_status == 1:  # 正在分析
    #     return render_template('binary.html', complete=1)
    # else:  # 已经分析
    #     global _g_mach_info
    #     global _g_method_hub
    #     return render_template('binary.html', complete=2, mach_info=_g_mach_info, method_hub=_g_method_hub)
    # return '''
    # <html>
    # <head><title>Analysis</title></head>
    # <body><h1>Access error!</h1></body>
    # </html>
    # '''

def extract_from_zip(path):
    zip_file = zipfile.ZipFile(path)
    target_name = zip_file.namelist()[0][:-1]
    zip_file.extractall(app.config['UPLOAD_FOLDER'])
    return os.path.join(app.config['UPLOAD_FOLDER'], target_name)


@app.route('/upload', methods=['POST'])
def upload_file():

    if 'file' in request.files:
        file = request.files['file']
        file_name = file.filename
        if filter_file_type(file_name):
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], file_name)
            if os.path.exists(file_path):
                os.remove(file_path)
            file.save(file_path)
            if file_name.split('.')[-1] == 'zip':
                app_path = extract_from_zip(file_path)
            else:
                app_path = file_path
            file_md5 = md5_for_file(file_path)
            store_md5_with_path(file_md5, app_path)
            return 'OK' + file_md5
    return 'Error'


if __name__ == '__main__':
    # webbrowser.open('http://127.0.0.1:5000/')
    app.run()
