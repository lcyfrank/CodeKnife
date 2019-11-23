import sys
import os
import shutil
import zipfile
import plistlib
from utils import md5_for_file
from static_analysis import static_analysis
from models.basic_info import ApplicationBasicInfo, permission_pairs


def extract_app_path_from_ipa(ipa_path):
    _, file_type = os.path.splitext(ipa_path)
    if file_type == '.ipa':
        try:
            target_ipa_file = zipfile.ZipFile(ipa_path)
        except Exception as _:
            target_ipa_file = None
        if target_ipa_file is None:
            return None
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

    app_info_plist = os.path.join(target_app_path, 'Info.plist')
    basic_info = ApplicationBasicInfo(target_app_path)

    # 提取 plist 文件内容
    with open(app_info_plist, 'rb') as app_info_plist:
        plist_content = plistlib.load(app_info_plist)

        if 'CFBundleDisplayName' in plist_content:
            display_name = plist_content['CFBundleDisplayName']
        else:
            display_name = plist_content['CFBundleName']
        basic_info.display_name = display_name
        basic_info.execute_path = plist_content['CFBundleExecutable']
        device_family = plist_content['UIDeviceFamily']
        if 1 in device_family and 2 in device_family:
            basic_info.platform = 'Universal'
        elif 1 in device_family:
            basic_info.platform = 'iPhone'
        else:
            basic_info.platform = 'iPad'
        basic_info.operating_system = plist_content['MinimumOSVersion']
        basic_info.execute_hash = md5_for_file(os.path.join(target_app_path, basic_info.execute_path))
        basic_info.bundle_identifier = plist_content['CFBundleIdentifier']
        if 'CFBundleIcons' in plist_content:
            icon_file = plist_content['CFBundleIcons']['CFBundlePrimaryIcon']['CFBundleIconFiles'][0]
            icon_file_path = os.path.join(target_app_path, icon_file) + '.png'
            if not os.path.exists(icon_file_path):
                icon_file += '@2x'
                icon_file_path = os.path.join(target_app_path, icon_file) + '.png'
            icon_file += '.png'
            if os.path.exists(icon_file_path):
                shutil.copy(icon_file_path, 'static/imgs/icons/' + basic_info.execute_hash + '.png')
            basic_info.icon_path = basic_info.execute_hash + '.png'
        basic_info.app_version = plist_content['CFBundleShortVersionString']

        # URL Schemas
        if 'CFBundleURLTypes' in plist_content:
            url_types = plist_content['CFBundleURLTypes']
            for url_type in url_types:
                if 'CFBundleURLSchemes' in url_type:
                    for url_schema in url_type['CFBundleURLSchemes']:
                        basic_info.url_schemas.append(url_schema)

        # Supported Document Type
        if 'CFBundleDocumentTypes' in plist_content:
            document_types = plist_content['CFBundleDocumentTypes']
            for document_type in document_types:
                if 'CFBundleTypeName' in document_type:
                    basic_info.supported_document_type.append(document_type['CFBundleTypeName'])

        basic_info.SDK_version = plist_content['DTSDKName']
        basic_info.SDK_build = plist_content['DTSDKBuild']
        basic_info.Xcode_version = plist_content['DTXcode']
        basic_info.Xcode_build = plist_content['DTXcodeBuild']
        basic_info.machine_build = plist_content['BuildMachineOSBuild']
        basic_info.compiler = plist_content['DTCompiler']

        # Requested Permissions
        for permission_key in permission_pairs:
            if permission_key in plist_content:
                permission = (permission_key, permission_pairs[permission_key], plist_content[permission_key])
                basic_info.requested_permissions.append(permission)

        # Developed Files
        # .html .css .js .db .plist .xml
        file_types = {'.html', '.css', '.js', '.db', '.plist', '.xml'}
        directory = [target_app_path]
        while len(directory) > 0:
            target_directory = directory[0]
            directory = directory[1:]
            for f in os.listdir(target_directory):
                if os.path.isdir(os.path.join(target_directory, f)):
                    directory.append(os.path.join(target_directory, f))
                else:
                    _, file_type = os.path.splitext(f)
                    if file_type in file_types:
                        file_directory = (target_directory + '/')[len(target_app_path) + 1:]
                        file_name = f
                        basic_info.developed_files.append((file_directory, file_name))

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
    # os.chdir(target_app_path)
    app_info_plist_path = os.path.join(target_app_path, 'Info.plist')
    app_name = None
    with open(app_info_plist_path, 'rb') as app_info_plist:
        plist_content = plistlib.load(app_info_plist)
        execute_file = plist_content['CFBundleExecutable']
        app_name = plist_content['CFBundleName']

    if execute_file is not None:
        execute_file_path = os.path.join(target_app_path, execute_file)
        static_analysis(execute_file_path, app_name)
