import pymongo
from models.basic_info import ApplicationBasicInfo
from models.mach_object import *
from models.inner_instruction import *
import json


def store_md5_with_path(md5, path):
    mongo_client = pymongo.MongoClient('mongodb://127.0.0.1:27017/')
    mongo_db = mongo_client['codeknife']
    file_path_col = mongo_db['file_path']
    condition = {'md5': md5}
    stored_path = file_path_col.find_one(condition)
    if stored_path is None:
        item = {
            'md5': md5,
            'path': path
        }
        file_path_col.insert_one(item)
    elif stored_path['path'] != path:
        # 更新
        stored_path['path'] = path
        file_path_col.update(stored_path)


def load_path_of_md5(md5):
    mongo_client = pymongo.MongoClient('mongodb://127.0.0.1:27017/')
    mongo_db = mongo_client['codeknife']
    file_path_col = mongo_db['file_path']
    file_path = file_path_col.find_one({'md5': md5})
    if file_path is None:
        return None
    return file_path['path']


def store_md5_with_basic_info(md5, basic_info: ApplicationBasicInfo):
    mongo_client = pymongo.MongoClient('mongodb://127.0.0.1:27017/')
    mongo_db = mongo_client['codeknife']
    basic_info_col = mongo_db['basic_info']

    condition = {'md5': md5}
    stored_basic_info = basic_info_col.find_one(condition)

    basic_info_dict = basic_info.__dict__.copy()
    basic_info_dict['md5'] = md5
    if stored_basic_info is None:
        basic_info_col.insert_one(basic_info_dict)
    else:
        basic_info_dict['_id'] = stored_basic_info['_id']
        basic_info_col.update(basic_info_dict)


def load_basic_info_of_md5(md5):
    mongo_client = pymongo.MongoClient('mongodb://127.0.0.1:27017/')
    mongo_db = mongo_client['codeknife']
    basic_info_col = mongo_db['basic_info']

    basic_info_dict = basic_info_col.find_one({'md5': md5})
    if basic_info_dict is None:
        return None
    del basic_info_dict['_id']
    del basic_info_dict['md5']

    basic_info = ApplicationBasicInfo(basic_info_dict['app_path'])
    basic_info.__dict__ = basic_info_dict
    return basic_info


def store_md5_with_mach_info(md5, mach_container: MachContainer):
    mongo_client = pymongo.MongoClient('mongodb://127.0.0.1:27017/')
    mongo_db = mongo_client['codeknife']
    mach_info_col = mongo_db['mach_info']

    condition = {'md5': md5}
    stored_mach_container_dict = mach_info_col.find_one(condition)

    mach_container_dict = mach_container.convert_to_dict()
    mach_container_dict['md5'] = md5
    if stored_mach_container_dict is None:
        mach_info_col.insert_one(mach_container_dict)
    else:
        mach_container_dict['_id'] = stored_mach_container_dict['_id']
        mach_info_col.update(mach_container_dict)


def load_mach_info_of_md5(md5):
    mongo_client = pymongo.MongoClient('mongodb://127.0.0.1:27017/')
    mongo_db = mongo_client['codeknife']
    mach_info_col = mongo_db['mach_info']

    mach_info_dict = mach_info_col.find_one({'md5': md5})
    if mach_info_dict is None:
        return None
    else:
        return MachContainer(mc_dict=mach_info_dict)


def store_md5_with_cs_instructions(md5, instructions, is_64_bit):
    '''
    存储反编译结果
    '''
    mongo_client = pymongo.MongoClient('mongodb://127.0.0.1:27017/')
    mongo_db = mongo_client['codeknife']
    cs_instructions_col = mongo_db['cs_instructions']

    condition = {'md5': md5, 'is_64_bit': is_64_bit}
    stored_instructions = cs_instructions_col.find_one(condition)

    instructions_dict = {'md5': md5, 'is_64_bit': is_64_bit}
    instructions_list = []
    for method_instructions in instructions:
        method_instructions_list = []
        for instruction in method_instructions:
            method_instructions_list.append(instruction.convert_to_dict())
        instructions_list.append(method_instructions_list)
    instructions_dict['instructions'] = instructions_list

    if stored_instructions is None:
        cs_instructions_col.insert_one(instructions_dict)
    else:
        instructions_dict['_id'] = stored_instructions['_id']
        cs_instructions_col.update_one(instructions_dict)


def load_cs_instructions_of_md5(md5, is_64_bit):
    mongo_client = pymongo.MongoClient('mongodb://127.0.0.1:27017/')
    mongo_db = mongo_client['codeknife']
    cs_instructions_col = mongo_db['cs_instructions']

    instructions_dict = cs_instructions_col.find_one({'md5': md5, 'is_64_bit': is_64_bit})
    if instructions_dict is None:
        return None
    else:
        instructions = []
        for method_instruction_list in instructions_dict['instructions']:
            method_instructions = []
            for instruction_dict in method_instruction_list:
                method_instructions.append(CSInstruction(csi_dict=instruction_dict))
            instructions.append(method_instructions)
        return instructions


def store_md5_with_method_hub(md5, method_hub, tag):
    mongo_client = pymongo.MongoClient('mongodb://127.0.0.1:27017/')
    mongo_db = mongo_client['codeknife']
    method_hub_col = mongo_db['method_hub']

    condition = {'md5': md5, 'tag': tag}
    stored_method_hub = method_hub_col.find_one(condition)

    if stored_method_hub is None:
        pass
    else:
        pass
