import sys
import os
import shutil
import zipfile
import plistlib
from static_analysis import static_analysis
from models.basic_info import ApplicationBasicInfo


def extract_app_path_from_ipa(ipa_path):
    _, file_type = os.path.splitext(ipa_path)
    if file_type == '.ipa':
        target_ipa_file = zipfile.ZipFile(ipa_path)
        if os.path.isdir('.tmp'):
            shutil.rmtree('.tmp')
        os.mkdir('.tmp')
        target_ipa_file.extractall('.tmp')
        target_ipa_file.close()
        tmp_file = os.listdir('.tmp/Payload')[0]
        return '.tmp/Payload/' + tmp_file
    return None


def basic_analysis(path):
    _, file_type = os.path.splitext(path)
    target_app_path = None
    if file_type == '.ipa':
        target_app_path = extract_app_path_from_ipa(path)
    elif file_type == '.app':
        target_app_path = path

    if target_app_path is None:
        return None

    os.chdir(target_app_path)
    app_info_plist = 'Info.plist'

    basic_info = ApplicationBasicInfo(target_app_path)
    with open(app_info_plist, 'rb') as app_info_plist:
        plist_content = plistlib.load(app_info_plist)
        basic_info.execute_path = plist_content['CFBundleExecutable']
    return basic_info


if __name__ == '__main__':

    if len(sys.argv) < 2:
        print('[Error] Usage: python basic_analysis.py [Target IPA file/Target APP file]')
        exit(-1)

    target_file_path = sys.argv[1]
    if not os.path.exists(target_file_path):
        print('[Error] File \'%s\' is not exists' % target_file_path)
        exit(-1)

    _, file_type = os.path.splitext(target_file_path)

    target_app_path = None
    if file_type == '.ipa':
        target_app_path = extract_app_path_from_ipa(target_file_path)
    elif file_type == '.app':
        target_app_path = target_file_path

    if target_app_path is None:
        print('[Error] File \'%s\' is not IPA file or APP file' % target_file_path)
        exit(-1)

    execute_file = None
    os.chdir(target_app_path)
    app_info_plist_path = 'Info.plist'
    with open(app_info_plist_path, 'rb') as app_info_plist:
        plist_content = plistlib.load(app_info_plist)
        execute_file = plist_content['CFBundleExecutable']

    if execute_file is not None:
        static_analysis(execute_file)
