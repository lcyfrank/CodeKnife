import webbrowser
from flask import Flask, render_template, request, redirect, url_for, jsonify, session
import os
import zipfile
from basic_analysis import basic_analysis
from static_analysis import view_static_analysis
import threading
from queue import Queue
from utils import md5_for_file
from utils import time_to_str
from models.mach_object import *
from models.macho_method_hub import *
from models.mongo_storage import *
from cfg_generator import *
from urllib import parse

ALLOWED_EXTENSIONS = {'app', 'ipa'}
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'upload'
app.jinja_env.add_extension('jinja2.ext.do')

_g_process_msg_queues = {}
_g_md5_messages = {}
_g_md5_object = {}

_g_load_commands_name = {
    1: 'LC_SEGMENT', 2: 'LC_SYMTAB', 3: 'LC_SYMSEG', 4: 'LC_THREAD',
    5: 'LC_UNIXTHREAD', 6: 'LC_LOADFVMLIB', 7: 'LC_IDFVMLIB', 8: 'LC_IDENT', 9: 'LC_FVMFILE',
    0xa: 'LC_PREPAGE', 0xb: 'LC_DYSYMTAB', 0xc: 'LC_LOAD_DYLIB', 0xd: 'LC_ID_DYLIB', 0xe: 'LC_LOAD_DYLINKER',
    0xf: 'LC_ID_DYLINKER', 0x10: 'LC_PREBOUND_DYLIB', 0x11: 'LC_ROUTINES', 0x12: 'LC_SUB_FRAMEWORK',
    0x13: 'LC_SUB_UMBRELLA',
    0x14: 'LC_SUB_CLIENT', 0x15: 'LC_SUB_LIBRARY', 0x16: 'LC_TWOLEVEL_HINTS', 0x17: 'LC_PREBIND_CKSUM',
    (0x18 | 0x80000000): 'LC_LOAD_WEAK_DYLIB',
    0x19: 'LC_SEGMENT_64', 0x1a: 'LC_ROUTINES_64', 0x1b: 'LC_UUID', (0x1c | 0x80000000): 'LC_RPATH',
    0x1d: 'LC_CODE_SIGNATURE',
    0x1e: 'LC_SEGMENT_SPLIT_INFO', (0x1f | 0x80000000): 'LC_REEXPORT_DYLIB', 0x20: 'LC_LAZY_LOAD_DYLIB',
    0x21: 'LC_ENCRYPTION_INFO',
    0x22: 'LC_DYLD_INFO', (0x22 | 0x80000000): 'LC_DYLD_INFO_ONLY', (0x23 | 0x80000000): 'LC_LOAD_UPWARD_DYLIB',
    0x24: 'LC_VERSION_MIN_MACOSX',
    0x25: 'LC_VERSION_MIN_IPHONEOS', 0x26: 'LC_FUNCTION_STARTS', 0x27: 'LC_DYLD_ENVIRONMENT',
    (0x28 | 0x80000000): 'LC_MAIN',
    0x29: 'LC_DATA_IN_CODE', 0x2a: 'LC_SOURCE_VERSION', 0x2b: 'LC_DYLIB_CODE_SIGN_DRS', 0x2c: 'LC_ENCRYPTION_INFO_64',
    0x2d: 'LC_LINKER_OPTION',
    0x2e: 'LC_LINKER_OPTIMIZATION_HINT', 0x2f: 'LC_VERSION_MIN_TVOS', 0x30: 'LC_VERSION_MIN_WATCHOS', 0x31: 'LC_NOTE',
    0x32: 'LC_BUILD_VERSION'
}


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
    global _g_md5_object

    file_md5 = request.args.get('md5')
    if file_md5 in _g_process_msg_queues:  # 正在分析
        msg_queue = _g_process_msg_queues[file_md5]
        try:
            msg = msg_queue.get(block=False)
        except:
            msg = ''
        processing = msg != 'Analyze all methods complete' and len(msg) > 0
        if msg == 'Analyze all methods complete':
            del _g_process_msg_queues[file_md5]
            basic_info = load_basic_info_of_md5(file_md5)
            binary_md5 = basic_info.execute_hash
            mach_container = load_mach_container_of_md5(binary_md5)
            method_hub = load_method_hub_of_md5(binary_md5, 0)
            _g_md5_object[file_md5] = (mach_container, method_hub)

        response_dict = {
            'success': True,
            'data': {
                'processing': processing,
                'msg': msg
            }
        }
        return jsonify(response_dict)
    else:
        if file_md5 in _g_md5_object:  # 分析完成
            response_dict = {
                'success': True,
                'data': {
                    'processing': False,
                    'msg': 'Analyse all methods complete'
                }
            }
        else:
            response_dict = {
                'success': True,
                'data': {
                    'processing': False,
                    'msg': 'Something error'
                }
            }
        return jsonify(response_dict)


@app.route('/analysis/binary/<file_md5>')
def binary_analysis(file_md5):
    # return render_template('binary.html', complete=2, md5=file_md5, mach_info='ddd', method_hub='ddd')
    global _g_md5_object
    global _g_load_commands_name

    basic_info = load_basic_info_of_md5(file_md5)
    if basic_info is not None:

        if file_md5 not in _g_process_msg_queues:  # 说明没有正在分析
            if file_md5 in _g_md5_object:  # 分析完成
                mach_info, method_hub = _g_md5_object[file_md5]
                return render_template('binary.html', complete=2, md5=file_md5, mach_info=mach_info,
                                       method_hub=method_hub, load_commands_name=_g_load_commands_name)
            else:
                _g_process_msg_queues[file_md5] = Queue(100)

                app_name = basic_info.display_name
                app_path = os.path.join(basic_info.app_path, basic_info.execute_path)
                t = threading.Thread(target=view_static_analysis,
                                     args=(app_path, app_name, 0, _g_process_msg_queues[file_md5]))
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


@app.route('/analysis/binary/<file_md5>/classes')
def binary_analysis_classes(file_md5):
    global _g_md5_object
    global _g_process_msg_queues

    basic_info = load_basic_info_of_md5(file_md5)
    if basic_info is not None:
        if file_md5 not in _g_process_msg_queues:  # 说明没有正在分析
            if file_md5 in _g_md5_object:  # 分析完成
                mach_info, method_hub = _g_md5_object[file_md5]
                mach_object = mach_info.mach_objects[0]
                class_name = request.args.get('class')
                cat_data = request.args.get('cat')
                search_key: str = request.args.get('search')
                # if search_key is None:
                #     search_key = ''
                cat_name = None
                cat_class = None
                if cat_data is not None:
                    cat_name = cat_data.split(' ')[0]
                    cat_class = cat_data.split(' ')[1]

                class_name_list = []
                for data_address in mach_object.class_datas:
                    class_data = mach_object.class_datas[data_address]
                    if search_key is None or search_key.lower() in class_data.name.lower():
                        class_name_list.append(class_data.name)

                cat_name_list = []
                for data_address in mach_object.cat_datas:
                    cat_data = mach_object.cat_datas[data_address]
                    if search_key is None or search_key.lower() in cat_data.name.lower() or search_key.lower() in cat_data._class.lower():
                        cat_name_list.append((cat_data.name, cat_data._class))

                methods_type = None
                if class_name is not None:
                    data_address = mach_object.class_name_address[class_name]
                    data_address_key = hex(data_address)
                    class_data = mach_object.class_datas[data_address_key]
                    methods_type = mach_object.methods_type
                else:
                    class_data = None

                if cat_name is not None:
                    data_address = mach_object.cat_datas_address[(cat_class, cat_name)]
                    data_address_key = hex(data_address)
                    cat_data = mach_object.cat_datas[data_address_key]
                    methods_type = mach_object.methods_type
                else:
                    cat_data = None

                return render_template('classes.html', md5=file_md5, key=search_key,
                                       class_name_list=class_name_list, cat_name_list=cat_name_list,
                                       class_data=class_data, cat_data=cat_data,
                                       methods_type=methods_type)
    return '''
    <html>
    <head><title>Analysis</title></head>
    <body><h1>Access error!</h1></body>
    </html>
    '''


@app.route('/analysis/binary/<file_md5>/methods')
def binary_analysis_methods(file_md5):
    global _g_md5_object
    global _g_process_msg_queues

    basic_info = load_basic_info_of_md5(file_md5)
    if basic_info is not None:
        if file_md5 not in _g_process_msg_queues:
            if file_md5 in _g_md5_object:
                mach_info, method_hub = _g_md5_object[file_md5]

                select = request.args.get('sel')
                address = request.args.get('address')
                if address:
                    address = int(address)

                method_title = None
                method_name_list = []
                class_name_list = []
                for class_name in method_hub.method_insns:
                    class_name_list.append(class_name)
                    if select is not None and class_name != select:
                        continue
                    class_methods = method_hub.method_insns[class_name]
                    for method_insn in class_methods:
                        method_insn_address = method_insn.entry_block.instructions[0].address
                        method_insn_address_key = hex(method_insn_address)
                        if method_insn_address_key in method_hub.cs_insns:
                            if method_insn.class_name[0] == '$':
                                if address and method_insn_address == address:
                                    method_title = method_insn.method_name
                                method_name_list.append((method_insn_address, method_insn.method_name))
                            else:
                                if address and method_insn_address == address:
                                    method_title = '[' + class_name + ' ' + method_insn.method_name + ']'
                                method_name_list.append((method_insn_address, '[' + class_name + ' ' + method_insn.method_name + ']'))

                cfg = None
                if address:
                    address_key = hex(address)
                    method_insn = method_hub.cs_insns[address_key]
                    if address_key in mach_info.mach_objects[0].methods:
                        class_name, method_name = mach_info.mach_objects[0].methods[address_key]

                        def cfg_provider(class_name, imp_name):
                            method_instruction = method_hub.get_method_insn(class_name, imp_name)
                            return method_instruction

                        method_instruction = method_hub.get_method_insn(class_name, method_name)
                        cfg = generate_cfg(method_instruction, cfg_provider, False).convert_to_dict()
                else:
                    method_insn = None

                return render_template('methods.html', md5=file_md5, select=select,
                                       class_name_list=class_name_list, method_name_list=method_name_list,
                                       method_insns=method_insn, cfg_model=cfg, method_title=method_title)
    return '''
    <html>
    <head><title>Analysis</title></head>
    <body><h1>Access error!</h1></body>
    </html>
    '''


@app.route('/analysis/binary/<file_md5>/checkers')
def binary_analysis_checkers(file_md5):
    global _g_md5_object
    global _g_md5_messages

    basic_info = load_basic_info_of_md5(file_md5)
    if basic_info is not None:
        if file_md5 not in _g_process_msg_queues:
            if file_md5 in _g_md5_object:
                mach_info, method_hub = _g_md5_object[file_md5]
                current_dir = os.getcwd()
                checkers_dir = os.path.join(os.path.dirname(current_dir), 'checker')
                if os.path.exists(checkers_dir):
                    checkers = os.listdir(checkers_dir)
                    checkers_path = []
                    for checker in checkers:
                        if os.path.splitext(checker)[-1] == '.py' and checker != '__init__.py':
                            checker_path = os.path.join(checkers_dir, checker)
                            checker_size = round(os.path.getsize(checker_path) / 1024, 2)
                            checker_create = time_to_str(os.path.getctime(checker_path))
                            checker_modify = time_to_str(os.path.getmtime(checker_path))
                            checker_dict = {'size': checker_size, 'create': checker_create, 'modify': checker_modify,
                                            'path': checker_path, 'name': checker}
                            print(checker_dict)
                            checkers_path.append(checker_dict)
                else:
                    checkers_path = []
                return render_template('checkers.html', md5=file_md5, checkers=checkers_path)
    return '''
    <html>
    <head><title>Analysis</title></head>
    <body><h1>Access error!</h1></body>
    </html>
    '''


@app.route('/analysis/binary/<file_md5>/checkers/edit')
def binary_analysis_checkers_edit(file_md5):
    checker_name = request.args.get('ch')
    if checker_name is None:
        return render_template('checkers_edit.html', md5=file_md5)
    current_dir = os.getcwd()
    checkers_dir = os.path.join(os.path.dirname(current_dir), 'checker')
    checker_path = os.path.join(checkers_dir, checker_name + '.py')
    with open(checker_path, 'r') as file:
        content = file.read()

    return render_template('checkers_edit.html', md5=file_md5, checker_file=checker_name + '.py', checker_code=content)


@app.route('/analysis/binary/<file_md5>/execute', methods=['POST'])
def binary_analysis_execute_checker(file_md5):
    code_bytes: bytes = request.stream.read()
    code = code_bytes.decode('utf-8')
    # Execute this code
    return 'OK'


@app.route('/analysis/binary/save', methods=['POST'])
def binary_analysis_save_checker():
    save_data: bytes = request.stream.read()
    save_data_str = save_data.decode('utf-8')
    save_data_json = parse.parse_qs(save_data_str)

    current_dir = os.getcwd()
    checkers_dir = os.path.join(os.path.dirname(current_dir), 'checker')

    new_file_name = save_data_json['name'][0]
    new_file_path = os.path.join(checkers_dir, new_file_name + '.py')

    if save_data_json['action'][0] == 'new':
        # New
        duplicate_index = 1
        temp_new_file_name = new_file_name
        while os.path.exists(new_file_path):
            temp_new_file_name = new_file_name + '(' + str(duplicate_index) + ')'
            new_file_path = os.path.join(checkers_dir, temp_new_file_name + '.py')
            duplicate_index += 1

        new_file = open(new_file_path, 'w')
        if 'content' in save_data_json:
            new_file.write(save_data_json['content'][0])
        new_file.close()
        return temp_new_file_name
    else:
        old_file_name = save_data_json['old'][0]
        old_file_path = os.path.join(checkers_dir, old_file_name)
        os.remove(old_file_path)

        duplicate_index = 1
        temp_new_file_name = new_file_name
        while os.path.exists(new_file_path):
            temp_new_file_name = new_file_name + '(' + str(duplicate_index) + ')'
            new_file_path = os.path.join(checkers_dir, temp_new_file_name + '.py')
            duplicate_index += 1

        new_file = open(new_file_path, 'w')
        if 'content' in save_data_json:
            new_file.write(save_data_json['content'][0])
        new_file.close()
        return temp_new_file_name


@app.route('/analysis/binary/delete', methods=['POST'])
def binary_analysis_delete_checker():
    file_data: bytes = request.stream.read()
    file_name = file_data.decode('utf-8')

    current_dir = os.getcwd()
    checkers_dir = os.path.join(os.path.dirname(current_dir), 'checker')
    file_path = os.path.join(checkers_dir, file_name + '.py')
    if os.path.exists(file_path):
        os.remove(file_path)
        return 'OK'
    return 'Err'


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
