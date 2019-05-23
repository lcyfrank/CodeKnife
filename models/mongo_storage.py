import pymongo
from models.basic_info import ApplicationBasicInfo
from models.mach_object import *
from models.inner_instruction import *
from models.macho_method_hub import *
import time
import os
import pickle
from bson import ObjectId
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
        file_path_col.update_one({'_id': stored_path['_id']}, {'$set': stored_path})


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
        basic_info_col.update_one({'_id': stored_basic_info['_id']}, {'$set': basic_info_dict})


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


def store_mach_info(mach_info: MachObject, data_dir):
    mongo_client = pymongo.MongoClient('mongodb://127.0.0.1:27017/')
    mongo_db = mongo_client['codeknife']
    mach_info_col = mongo_db['mach_info']

    mach_info_path = os.path.join(data_dir, 'mach_info')
    if not os.path.exists(mach_info_path):
        os.mkdir(mach_info_path)

    mach_info_dict = {
        'type': mach_info.type,  # Number
        'offset': mach_info.offset,  # Number
        'is_64_bit': mach_info.is_64_bit,  # Number
        'cpu_type': mach_info.cpu_type,  # Number
        'cpu_subtype': mach_info.cpu_subtype,  # Number
        'file_type': mach_info.file_type,  # Number
        'ncmds': mach_info.ncmds,  # Number
        'text_addr': mach_info.text_addr  # Number
    }

    insert_fields_key = [('dylib_frameworks_path', False), ('dylib_frameworks_pair', True),
                         ('notification_handler', False), ('notification_poster', False),
                         ('symbols', False), ('dylibs', False), ('functions', False),
                         ('statics', False), ('statics_class', False), ('class_methods', True),
                         ('methods', False), ('class_name_address', False), ('cat_datas_address', True),
                         ('cfstrings', False), ('ivar_refs', False), ('ivars', False)]
    temp_mach_info_dict = mach_info.__dict__
    for field_key, should_str in insert_fields_key:
        if should_str:
            result = mach_info_col.insert_one({'type': field_key, 'data': str(temp_mach_info_dict[field_key])})
        else:
            result = mach_info_col.insert_one({'type': field_key, 'data': temp_mach_info_dict[field_key]})
        mach_info_dict[field_key] = result.inserted_id

    # _cmds
    cmds_col = mongo_db['cmds']
    _cmds = {}
    for key in mach_info._cmds:
        if key not in _cmds:
            _cmds[key] = []
        for offset, cmd in mach_info._cmds[key]:
            cmd_dict = cmd.convert_to_dict()
            result = cmds_col.insert_one({'offset': offset, 'data': cmd_dict})
            _cmds[key].append(result.inserted_id)
    mach_info_dict['_cmds'] = _cmds

    # _sections
    sections_col = mongo_db['sections']
    _sections = {}
    for key in mach_info._sections:
        section, index = mach_info._sections[key]
        section_dict = section.convert_to_dict()
        result = sections_col.insert_one({'index': index, 'data': section_dict})
        _sections[key] = result.inserted_id
    mach_info_dict['_sections'] = _sections

    # dylib_frameworks_mach
    dylib_frameworks_mach = {}
    for dylib_path in mach_info.dylib_frameworks_mach:
        dylib_frameworks_mach[dylib_path] = str(store_mach_info(mach_info.dylib_frameworks_mach[dylib_path], data_dir))
    mach_info_dict['dylib_frameworks_mach'] = str(dylib_frameworks_mach)

    # methods_type
    # methods_type_col = mongo_db['methods_type']
    # methods_type = []
    # for key in mach_info.methods_type:
    #     class_name, method_name = key
    #     result = methods_type_col.insert_one({'class_name': class_name, 'method_name': method_name, 'data': mach_info.methods_type[key].convert_to_dict()})
    #     methods_type.append(result.inserted_id)
    # mach_info_dict['methods_type'] = methods_type
    methods_type = []
    for key in mach_info.methods_type:
        class_name, method_name = key
        methods_type.append({'class_name': class_name, 'method_name': method_name, 'data': mach_info.methods_type[key].convert_to_dict()})
    methods_type_path = os.path.join(mach_info_path, '000' + str(int(time.time() * 1000)))
    pickle.loads(pickle.dumps(methods_type))
    with open(methods_type_path, 'wb') as methods_type_file:
        methods_type_file.write(pickle.dumps(methods_type))
    mach_info_dict['methods_type'] = methods_type_path

    # class_datas
    # class_datas_col = mongo_db['class_datas']
    # class_datas = []
    # for key in mach_info.class_datas:
    #     result = class_datas_col.insert_one({'data_address': key, 'data': mach_info.class_datas[key].convert_to_dict()})
    #     class_datas.append(result.inserted_id)
    # mach_info_dict['class_datas'] = class_datas
    class_datas = []
    for key in mach_info.class_datas:
        class_datas.append({'data_address': key, 'data': mach_info.class_datas[key].convert_to_dict()})
    class_datas_path = os.path.join(mach_info_path, '001' + str(int(time.time() * 1000)))
    pickle.loads(pickle.dumps(class_datas))
    with open(class_datas_path, 'wb') as class_datas_file:
        class_datas_file.write(pickle.dumps(class_datas))
    mach_info_dict['class_datas'] = class_datas_path

    # cat_datas
    # cat_datas_col = mongo_db['cat_datas']
    # cat_datas = []
    # for key in mach_info.cat_datas:
    #     result = cat_datas_col.insert_one({'data_address': key, 'data': mach_info.cat_datas[key].convert_to_dict()})
    #     cat_datas.append(result.inserted_id)
    # mach_info_dict['cat_datas'] = cat_datas
    cat_datas = []
    for key in mach_info.cat_datas:
        cat_datas.append({'data_address': key, 'data': mach_info.cat_datas[key].convert_to_dict()})
    cat_datas_path = os.path.join(mach_info_path, '010' + str(int(time.time() * 1000)))
    pickle.loads(pickle.dumps(cat_datas))
    with open(cat_datas_path, 'wb') as cat_datas_file:
        cat_datas_file.write(pickle.dumps(cat_datas))
    mach_info_dict['cat_datas'] = cat_datas_path

    # block_methods
    # block_methods_col = mongo_db['block_methods']
    # block_methods = []
    # for key in mach_info.block_methods:
    #     result = block_methods_col.insert_one({'data_address': key, 'data': mach_info.block_methods[key].convert_to_dict()})
    #     block_methods.append(result.inserted_id)
    # mach_info_dict['block_methods'] = block_methods
    block_methods = []
    for key in mach_info.block_methods:
        block_methods.append({'data_address': key, 'data': mach_info.block_methods[key].convert_to_dict()})
    block_methods_path = os.path.join(mach_info_path, '011' + str(int(time.time() * 1000)))
    pickle.loads(pickle.dumps(block_methods))
    with open(block_methods_path, 'wb') as block_methods_file:
        block_methods_file.write(pickle.dumps(block_methods))
    mach_info_dict['block_methods'] = block_methods_path

    # save bytes and text
    bytes_file_path = os.path.join(mach_info_path, '100' + str(int(time.time() * 1000)))
    with open(bytes_file_path, 'wb') as bytes_file:
        bytes_file.write(mach_info.bytes)
    mach_info_dict['bytes'] = bytes_file_path

    text_file_path = os.path.join(mach_info_path, '101' + str(int(time.time() * 1000)))
    with open(text_file_path, 'wb') as text_file:
        text_file.write(mach_info.text)
    mach_info_dict['text'] = text_file_path

    result = mach_info_col.insert_one({'type': 'mach_info', 'data': mach_info_dict})
    return result.inserted_id


def load_mach_info(id):
    mongo_client = pymongo.MongoClient('mongodb://127.0.0.1:27017/')
    mongo_db = mongo_client['codeknife']
    mach_info_col = mongo_db['mach_info']

    mach_info_dict = mach_info_col.find_one({'type': 'mach_info', '_id': id})
    if mach_info_dict is None:
        return None
    else:
        mach_info_dict = (mach_info_dict['data'])
        mach_info = MachObject()

        direct_fields_keys = ['type', 'offset', 'is_64_bit', 'cpu_type', 'cpu_subtype', 'file_type',
                              'ncmds', 'text_addr']
        for field_key in direct_fields_keys:
            mach_info.__dict__[field_key] = mach_info_dict[field_key]

        insert_fields_key = [('dylib_frameworks_path', False), ('dylib_frameworks_pair', True),
                             ('notification_handler', False), ('notification_poster', False),
                             ('symbols', False), ('dylibs', False), ('functions', False),
                             ('statics', False), ('statics_class', False), ('class_methods', True),
                             ('methods', False), ('class_name_address', False), ('cat_datas_address', True),
                             ('cfstrings', False), ('ivar_refs', False), ('ivars', False)]
        for field_key, should_str in insert_fields_key:
            field_value = mach_info_col.find_one({'type': field_key, '_id': mach_info_dict[field_key]})['data']
            if should_str:
                print(field_key)
                mach_info.__dict__[field_key] = eval(field_value)
            else:
                mach_info.__dict__[field_key] = field_value

        # dylib_frameworks_mach
        mach_info.dylib_frameworks_mach = {}
        dylib_frameworks_mach = eval(mach_info_dict['dylib_frameworks_mach'])
        for dylib_path in dylib_frameworks_mach:
            dylib_mach_info = load_mach_info(ObjectId(dylib_frameworks_mach[dylib_path]))
            mach_info.dylib_frameworks_mach[dylib_path] = dylib_mach_info

        # _cmds
        cmds_col = mongo_db['cmds']
        mach_info._cmds = {}
        for key in mach_info_dict['_cmds']:
            if key not in mach_info._cmds:
                mach_info._cmds[key] = []
            for cmd_id in mach_info_dict['_cmds'][key]:
                cmd_dict = cmds_col.find_one({'_id': cmd_id})
                offset = cmd_dict['offset']
                cmd_data = LoadCommand.parse_from_dict(cmd_dict['data'])
                mach_info._cmds[key].append((offset, cmd_data))

        # _sections
        sections_col = mongo_db['sections']
        mach_info._sections = {}
        for key in mach_info_dict['_sections']:
            section_id = mach_info_dict['_sections'][key]
            section_dict = sections_col.find_one({'_id': section_id})
            index = section_dict['index']
            if mach_info.is_64_bit:
                section_data = Section64.parse_from_dict(section_dict['data'])
            else:
                section_data = Section.parse_from_dict(section_dict['data'])
            mach_info._sections[key] = (section_data, index)

        # methods_type
        # methods_type_col = mongo_db['methods_type']
        # mach_info.methods_type = {}
        # for method_type_id in mach_info_dict['methods_type']:
        #     methods_type_dict = methods_type_col.find_one({'_id': method_type_id})
        #     key = (methods_type_dict['class_name'], methods_type_dict['method_name'])
        #     data = MethodData(md_dict=methods_type_dict['data'])
        #     mach_info.methods_type[key] = data
        mach_info.methods_type = {}
        methods_type_path = mach_info_dict['methods_type']
        with open(methods_type_path, 'rb') as methods_type_file:
            methods_type = pickle.loads(methods_type_file.read())
            for method_type_dict in methods_type:
                key = (method_type_dict['class_name'], method_type_dict['method_name'])
                data = MethodData(md_dict=method_type_dict['data'])
                mach_info.methods_type[key] = data

        # class_datas
        # class_datas_col = mongo_db['class_datas']
        # mach_info.class_datas = {}
        # for class_data_id in mach_info_dict['class_datas']:
        #     class_data_dict = class_datas_col.find_one({'_id': class_data_id})
        #     key = class_data_dict['data_address']
        #     data = ClassData(cd_dict=class_data_dict['data'])
        #     mach_info.class_datas[key] = data
        mach_info.class_datas = {}
        class_datas_path = mach_info_dict['class_datas']
        with open(class_datas_path, 'rb') as class_datas_file:
            class_datas = pickle.loads(class_datas_file.read())
            for class_data_dict in class_datas:
                key = class_data_dict['data_address']
                data = ClassData(cd_dict=class_data_dict['data'])
                mach_info.class_datas[key] = data

        # cat_datas
        # cat_datas_col = mongo_db['cat_datas']
        # mach_info.cat_datas = {}
        # for cat_data_id in mach_info_dict['cat_datas']:
        #     cat_data_dict = cat_datas_col.find_one({'_id': cat_data_id})
        #     key = cat_data_dict['data_address']
        #     data = CatData(cd_dict=cat_data_dict['data'])
        #     mach_info.cat_datas[key] = data
        mach_info.cat_datas = {}
        cat_datas_path = mach_info_dict['cat_datas']
        with open(cat_datas_path, 'rb') as cat_datas_file:
            cat_datas = pickle.loads(cat_datas_file.read())
            for cat_data_dict in cat_datas:
                key = cat_data_dict['data_address']
                data = CatData(cd_dict=cat_data_dict['data'])
                mach_info.cat_datas[key] = data

        # block_methods
        # block_methods_col = mongo_db['block_methods']
        # mach_info.block_methods = {}
        # for block_method_id in mach_info_dict['block_methods']:
        #     block_method_dict = block_methods_col.find_one({'_id': block_method_id})
        #     key = block_method_dict['data_address']
        #     data = BlockMethodData(bmd_dict=block_method_dict['data'])
        #     mach_info.block_methods[key] = data
        mach_info.block_methods = {}
        block_methods_path = mach_info_dict['block_methods']
        with open(block_methods_path, 'rb') as block_methods_file:
            block_methods = pickle.loads(block_methods_file.read())
            for block_method_dict in block_methods:
                key = block_method_dict['data_address']
                data = BlockMethodData(bmd_dict=block_method_dict['data'])
                mach_info.block_methods[key] = data

        bytes_file_path = mach_info_dict['bytes']
        with open(bytes_file_path, 'rb') as bytes_file:
            mach_info.bytes = bytes_file.read()

        text_file_path = mach_info_dict['text']
        with open(text_file_path, 'rb') as text_file:
            mach_info.text = text_file.read()

        return mach_info


def store_md5_with_mach_container(md5, mach_container: MachContainer):
    mongo_client = pymongo.MongoClient('mongodb://127.0.0.1:27017/')
    mongo_db = mongo_client['codeknife']
    mach_container_col = mongo_db['mach_container']

    data_dir = os.getcwd() + '/data'
    if not os.path.exists(data_dir):
        os.mkdir(data_dir)
    current_data_dir_path = os.path.join(data_dir, md5)
    if not os.path.exists(current_data_dir_path):
        os.mkdir(current_data_dir_path)

    mach_container_dict = {'is_fat': mach_container.is_fat, 'nfat_arch': mach_container.nfat_arch}
    mach_objects = []
    for mach_info in mach_container.mach_objects:
        mach_objects.append(store_mach_info(mach_info, current_data_dir_path))
    mach_container_dict['mach_objects'] = mach_objects
    mach_container_col.insert_one({'md5': md5, 'data': mach_container_dict})


def update_mach_container_of_md5(md5, mach_container: MachContainer):
    mongo_client = pymongo.MongoClient('mongodb://127.0.0.1:27017/')
    mongo_db = mongo_client['codeknife']
    mach_container_col = mongo_db['mach_container']

    data_dir = os.getcwd() + '/data'
    if not os.path.exists(data_dir):
        os.mkdir(data_dir)
    current_data_dir_path = os.path.join(data_dir, md5)
    if not os.path.exists(current_data_dir_path):
        os.mkdir(current_data_dir_path)

    mach_container_dict = mach_container_col.find_one({'md5': md5})
    if mach_container_dict is not None:
        data_dict = mach_container_dict['data']
        print(data_dict['mach_objects'])
        mach_objects = []
        for mach_info in mach_container.mach_objects:
            print('update mach_objectsdjklasdjfklsjlfsdklfksjfklsdjfkls')
            print(mach_info.dylib_frameworks_mach)
            print(mach_info.dylib_frameworks_pair)
            print(mach_info.dylib_frameworks_path)
            mach_objects.append(store_mach_info(mach_info, current_data_dir_path))  # 现在直接添加新的 Mach Object
        data_dict['mach_objects'] = mach_objects
        mach_container_col.update_one({'_id': mach_container_dict['_id']}, {'$set': mach_container_dict})


def load_mach_container_of_md5(md5):
    mongo_client = pymongo.MongoClient('mongodb://127.0.0.1:27017/')
    mongo_db = mongo_client['codeknife']
    mach_container_col = mongo_db['mach_container']

    mach_container_dict = mach_container_col.find_one({'md5': md5})
    if mach_container_dict is None:
        return None
    else:
        mach_container = MachContainer()
        mach_container_dict = mach_container_dict['data']

        mach_container.is_fat = mach_container_dict['is_fat']
        mach_container.nfat_arch = mach_container_dict['nfat_arch']
        mach_container.mach_objects = []
        for mach_info_id in mach_container_dict['mach_objects']:
            mach_container.mach_objects.append(load_mach_info(mach_info_id))
        return mach_container


def store_md5_with_cs_instructions(md5, instructions, is_64_bit):
    '''
    存储反编译结果
    '''
    mongo_client = pymongo.MongoClient('mongodb://127.0.0.1:27017/')
    mongo_db = mongo_client['codeknife']
    cs_instructions_col = mongo_db['cs_instructions']

    data_dir = os.getcwd() + '/data'
    if not os.path.exists(data_dir):
        os.mkdir(data_dir)
    current_data_dir_path = os.path.join(data_dir, md5)
    if not os.path.exists(current_data_dir_path):
        os.mkdir(current_data_dir_path)
    instruction_dir = os.path.join(current_data_dir_path, 'instruction')
    if not os.path.exists(instruction_dir):
        os.mkdir(instruction_dir)

    instructions_list = []
    for method_instructions in instructions:
        method_instructions_list = []
        for instruction in method_instructions:
            method_instructions_list.append(instruction.convert_to_dict())
        instructions_list.append(method_instructions_list)
    cs_instructions_path = os.path.join(instruction_dir, '00' + str(int(time.time() * 1000)))
    with open(cs_instructions_path, 'wb') as cs_instructions_file:
        cs_instructions_file.write(pickle.dumps(instructions_list))
    cs_instructions_col.insert_one({'md5': md5, 'is_64_bit': is_64_bit, 'data': cs_instructions_path})

    # instruction_ids = []
    # for method_instructions in instructions:
    #     method_instructions_list = []
    #     for instruction in method_instructions:
    #         method_instructions_list.append(instruction.convert_to_dict())
    #     result = cs_instructions_col.insert_one({'data': method_instructions_list})
    #     instruction_ids.append(result.inserted_id)
    # cs_instructions_col.insert_one({'md5': md5, 'is_64_bit': is_64_bit, 'data': instruction_ids})

    # condition = {'md5': md5, 'is_64_bit': is_64_bit}
    # stored_instructions = cs_instructions_col.find_one(condition)
    #
    # instructions_dict = {'md5': md5, 'is_64_bit': is_64_bit}
    # instructions_list = []
    # for method_instructions in instructions:
    #     method_instructions_list = []
    #     for instruction in method_instructions:
    #         method_instructions_list.append(instruction.convert_to_dict())
    #     instructions_list.append(method_instructions_list)
    # instructions_dict['instructions'] = instructions_list
    #
    # if stored_instructions is None:
    #     cs_instructions_col.insert_one(instructions_dict)
    # else:
    #     instructions_dict['_id'] = stored_instructions['_id']
    #     cs_instructions_col.update_one({'_id': stored_instructions['_id']}, {'$set': instructions_dict})


def load_cs_instructions_of_md5(md5, is_64_bit):
    mongo_client = pymongo.MongoClient('mongodb://127.0.0.1:27017/')
    mongo_db = mongo_client['codeknife']
    cs_instructions_col = mongo_db['cs_instructions']

    # instructions_list = []
    # for method_instructions in instructions:
    #     method_instructions_list = []
    #     for instruction in method_instructions:
    #         method_instructions_list.append(instruction.convert_to_dict())
    #     instructions_list.append(method_instructions_list)
    # cs_instructions_path = os.path.join(instruction_dir, '00' + str(int(time.time() * 1000)))
    # with open(cs_instructions_path, 'wb') as cs_instructions_file:
    #     cs_instructions_file.write(pickle.dumps(instructions_list))
    # cs_instructions_col.insert_one({'md5': md5, 'is_64_bit': is_64_bit, 'data': cs_instructions_path})

    instructions_dict = cs_instructions_col.find_one({'md5': md5, 'is_64_bit': is_64_bit})
    if instructions_dict is None:
        return None
    else:
        instructions_path = instructions_dict['data']
        instructions = []
        with open(instructions_path, 'rb') as instructions_file:
            instructions_list = pickle.loads(instructions_file.read())
            for method_instructions in instructions_list:
                method_instructions_list = []
                for instruction_dict in method_instructions:
                    method_instructions_list.append(CSInstruction(csi_dict=instruction_dict))
                instructions.append(method_instructions_list)

        return instructions

        # instructions = []
        # for instruction_id in instructions_ids:
        #     method_instructions = []
        #     method_instruction_list = cs_instructions_col.find_one({'_id': instruction_id})['data']
        #     for instruction_dict in method_instruction_list:
        #         method_instructions.append(CSInstruction(csi_dict=instruction_dict))
        #     instructions.append(method_instructions)
        # return instructions
    # if instructions_dict is None:
    #     return None
    # else:
    #     instructions = []
    #     for method_instruction_list in instructions_dict['instructions']:
    #         method_instructions = []
    #         for instruction_dict in method_instruction_list:
    #             method_instructions.append(CSInstruction(csi_dict=instruction_dict))
    #         instructions.append(method_instructions)
    #     return instructions


def store_md5_with_method_hub(md5, method_hub: MachoMethodHub, tag):
    mongo_client = pymongo.MongoClient('mongodb://127.0.0.1:27017/')
    mongo_db = mongo_client['codeknife']
    method_hub_col = mongo_db['method_hub']

    data_dir = os.getcwd() + '/data'
    if not os.path.exists(data_dir):
        os.mkdir(data_dir)
    current_data_dir_path = os.path.join(data_dir, md5)
    if not os.path.exists(current_data_dir_path):
        os.mkdir(current_data_dir_path)
    instruction_dir = os.path.join(current_data_dir_path, 'instruction')
    if not os.path.exists(instruction_dir):
        os.mkdir(instruction_dir)

    method_hub_dict = {}

    # mh_cs_insns_col = mongo_db['mh_cs_insns']
    # mh_cs_insns = {}
    # for key in method_hub.cs_insns:
    #     cs_insn_list = []
    #     for cs_insn in method_hub.cs_insns[key]:
    #         cs_insn_list.append(cs_insn.convert_to_dict())
    #     print(len(cs_insn_list))
    #     result = mh_cs_insns_col.insert_one({'data': cs_insn_list})
    #     mh_cs_insns[key] = result.inserted_id
    # method_hub_dict['cs_insns'] = mh_cs_insns
    mh_cs_insns = {}
    mh_cs_insns_path = os.path.join(instruction_dir, '0' + str(int(time.time() * 1000)))
    # mh_cs_insns_file = open(mh_cs_insns_path, 'ab')
    for key in method_hub.cs_insns:
        cs_insn_list = []
        for cs_insn in method_hub.cs_insns[key]:
            cs_insn_list.append(cs_insn.convert_to_dict())
        mh_cs_insns[key] = cs_insn_list
    with open(mh_cs_insns_path, 'wb') as mh_cs_insns_file:
        mh_cs_insns_file.write(pickle.dumps(mh_cs_insns))
    method_hub_dict['cs_insns'] = mh_cs_insns_path

    # mh_method_insns_col = mongo_db['mh_method_insns']
    # mh_method_insns = {}
    # for class_name in method_hub.method_insns:
    #     mh_method_insns[class_name] = []
    #     class_methods = method_hub.method_insns[class_name]
    #     for method_insn in class_methods:
    #         result = mh_method_insns_col.insert_one({'data': method_insn.convert_to_dict()})
    #         mh_method_insns[class_name].append(result.inserted_id)
    # method_hub_dict['method_insns'] = str(mh_method_insns)
    mh_method_insns = {}
    for class_name in method_hub.method_insns:
        mh_method_insns[class_name] = []
        class_methods = method_hub.method_insns[class_name]
        for method_insn in class_methods:
            mh_method_insns[class_name].append(method_insn.convert_to_dict())
    mh_method_insns_path = os.path.join(instruction_dir, '1' + str(int(time.time() * 1000)))
    with open(mh_method_insns_path, 'wb') as mh_method_insns_file:
        mh_method_insns_file.write(pickle.dumps(mh_method_insns))
    method_hub_dict['method_insns'] = mh_method_insns_path
    print('method_insns_path', mh_method_insns_path)

    print('md5and tag')
    print(md5, tag)
    method_hub_col.insert_one({'md5': md5, 'tag': tag, 'data': method_hub_dict})


def update_method_hub_of_md5(md5, method_hub: MachoMethodHub, tag, cs_insn_update=False, method_insn_update=False):
    print('aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa')
    mongo_client = pymongo.MongoClient('mongodb://127.0.0.1:27017/')
    mongo_db = mongo_client['codeknife']
    method_hub_col = mongo_db['method_hub']

    print('md5and tag')
    print(md5, tag)
    method_hub_dict = method_hub_col.find_one({'md5': md5, 'tag': tag})
    print(method_hub_dict)
    if method_hub_dict is not None:

        data_dict = method_hub_dict['data']

        if cs_insn_update:
            mh_cs_insns_path = data_dict['cs_insns']
            mh_cs_insns_dir = os.path.dirname(mh_cs_insns_path)
            if os.path.exists(mh_cs_insns_path):
                os.remove(mh_cs_insns_path)

            mh_cs_insns = {}
            for key in method_hub.cs_insns:
                cs_insn_list = []
                for cs_insn in method_hub.cs_insns[key]:
                    cs_insn_list.append(cs_insn.convert_to_dict())
                mh_cs_insns[key] = cs_insn_list
            mh_cs_insns_path = os.path.join(mh_cs_insns_dir, '0' + str(int(time.time() * 1000)))
            with open(mh_cs_insns_path, 'wb') as mh_cs_insns_file:
                mh_cs_insns_file.write(pickle.dumps(mh_cs_insns))
            data_dict['cs_insns'] = mh_cs_insns_path

        if method_insn_update:
            mh_method_insns_path = data_dict['method_insns']
            mh_method_insns_dir = os.path.dirname(mh_method_insns_path)
            if os.path.exists(mh_method_insns_path):
                os.remove(mh_method_insns_path)

            mh_method_insns = {}
            for class_name in method_hub.method_insns:
                mh_method_insns[class_name] = []
                class_methods = method_hub.method_insns[class_name]
                for method_insn in class_methods:
                    mh_method_insns[class_name].append(method_insn.convert_to_dict())
            mh_method_insns_path = os.path.join(mh_method_insns_dir, '1' + str(int(time.time() * 1000)))
            with open(mh_method_insns_path, 'wb') as mh_method_insns_file:
                mh_method_insns_file.write(pickle.dumps(mh_method_insns))
            data_dict['method_insns'] = mh_method_insns_path
            print('sdkjfklsdjfklsdjsdfsdfsdlfjskljflsdjkl')
            print('method_insns_path', mh_method_insns_path)

            # mh_method_insns = {}
            # for class_name in method_hub.method_insns:
            #     mh_method_insns[class_name] = []
            #     class_methods = method_hub.method_insns[class_name]
            #     for method_insn in class_methods:
            #         result = mh_method_insns_col.insert_one({'data': method_insn.convert_to_dict()})
            #         mh_method_insns[class_name].append(result.inserted_id)
            # data_dict['method_insns'] = str(mh_method_insns)
            # for class_name in mh_method_insns:
            #     for method_insn_id in mh_method_insns[class_name]:
            #         mh_method_insns_col.remove({'_id': method_insn_id})
        # if cs_insn_update:
        #
        #
        # if method_insn_update:
        #     mh_method_insns = {}
        #     for class_name in method_hub.method_insns:
        #         mh_method_insns[class_name] = []
        #         class_methods = method_hub.method_insns[class_name]
        #         for method_insn in class_methods:
        #             result = mh_method_insns_col.insert_one({'data': method_insn.convert_to_dict()})
        #             mh_method_insns[class_name].append(result.inserted_id)
        #     data_dict['method_insns'] = str(mh_method_insns)
        print(method_hub_dict['data'])
        print('Will update')
        method_hub_col.update_one({'_id': method_hub_dict['_id']}, {'$set': method_hub_dict})


def load_method_hub_of_md5(md5, tag):
    mongo_client = pymongo.MongoClient('mongodb://127.0.0.1:27017/')
    mongo_db = mongo_client['codeknife']
    method_hub_col = mongo_db['method_hub']

    method_hub_dict = method_hub_col.find_one({'md5': md5, 'tag': tag})
    if method_hub_dict is None:
        return None
    else:
        method_hub_dict = method_hub_dict['data']
        method_hub = MachoMethodHub()

        # mh_cs_insns_col = mongo_db['mh_cs_insns']
        mh_cs_insns_path = method_hub_dict['cs_insns']
        method_hub.cs_insns = {}
        with open(mh_cs_insns_path, 'rb') as mh_cs_insns_file:
            mh_cs_insns = pickle.loads(mh_cs_insns_file.read())
            for key in mh_cs_insns:
                cs_insns = []
                cs_insn_list = mh_cs_insns[key]
                for cs_insn_dict in cs_insn_list:
                    cs_insns.append(CSInstruction(csi_dict=cs_insn_dict))
                method_hub.cs_insns[key] = cs_insns

        # mh_cs_insns = method_hub_dict['cs_insns']
        # method_hub.cs_insns = {}
        # for key in mh_cs_insns:
        #     insn_id = mh_cs_insns[key]
        #     cs_insns = []
        #     cs_insn_list = mh_cs_insns_col.find_one({'_id': insn_id})['data']
        #     for cs_insn_dict in cs_insn_list:
        #         cs_insns.append(CSInstruction(csi_dict=cs_insn_dict))
        #     method_hub.cs_insns[key] = cs_insns

        mh_method_insns_path = method_hub_dict['method_insns']
        method_hub.method_insns = {}
        with open(mh_method_insns_path, 'rb') as mh_method_insns_file:
            mh_method_insns = pickle.loads(mh_method_insns_file.read())
            for class_name in mh_method_insns:
                method_hub.method_insns[class_name] = []
                for method_insn_dict in mh_method_insns[class_name]:
                    method_hub.method_insns[class_name].append(MethodInstructions(mi_dict=method_insn_dict))

        # mh_method_insns_col = mongo_db['mh_method_insns']
        # mh_method_insns = eval(method_hub_dict['method_insns'])
        # method_hub.method_insns = {}
        # for class_name in mh_method_insns:
        #     method_hub.method_insns[class_name] = []
        #     for method_insn_id in mh_method_insns[class_name]:
        #         method_insn_dict = mh_method_insns_col.find_one({'_id': method_insn_id})['data']
        #         method_insn = MethodInstructions(mi_dict=method_insn_dict)
        #         method_hub.method_insns[class_name].append(method_insn)
        return method_hub

