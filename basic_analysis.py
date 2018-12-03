import sys
import os
import shutil
import zipfile
import plistlib

if len(sys.argv) < 2:
    print('[Error] Usage: python basic_analysis.py [Target IPA file]')
    exit(-1)

target_ipa_path = sys.argv[1]
if not os.path.exists(target_ipa_path):
    print('[Error] File \'%s\' is not exists' % (target_ipa_path))
    exit(-1)

target_ipa_file = zipfile.ZipFile(target_ipa_path)

if os.path.isdir('.tmp'):
    shutil.rmtree('.tmp')
os.mkdir('.tmp')

target_ipa_file.extract('iTunesMetadata.plist', '.tmp')
target_ipa_file.close()

itunes_meta_file = open('.tmp/iTunesMetadata.plist', 'rb+')
itunes_meta_file.seek(-1, os.SEEK_END)
itunes_meta_file.truncate()
itunes_meta_file.close()

print(type(plistlib.readPlist('.tmp/iTunesMetadata.plist')))