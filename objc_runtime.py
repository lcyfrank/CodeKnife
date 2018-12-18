from utils import *


class ObjcBase():

    def __init__(self):
        pass

    @classmethod
    def parse_from_bytes(cls, _bytes):
        return cls()

    def get_size(self):
        return 0


class ObjcClass64(ObjcBase):

    OC_TOTAL_SIZE = 40
    OC_METACLASS_RANGE = (0, 8)
    OC_SUPERCLASS_RANGE = (8, 8)
    OC_CACHE_RANGE = (16, 8)
    OC_VTABLE_RANGE = (24, 8)
    OC_DATA_RANGE = (32, 8)

    def __init__(self):
        self.metaclass = 0
        self.superclass = 0
        self.cache = 0
        self.vtable = 0
        self.data = 0

    @classmethod
    def parse_from_bytes(cls, _bytes):
        oc = cls()
        oc.metaclass = parse_int(_bytes[0:8])
        oc.superclass = parse_int(_bytes[8:16])
        oc.cache = parse_int(_bytes[16:24])
        oc.vtable = parse_int(_bytes[24:32])
        oc.data = parse_int(_bytes[32:40])
        return oc

    def get_size(self):
        return ObjcClass64.OC_TOTAL_SIZE


class ObjcData64(ObjcBase):

    OD_TOTAL_SIZE = 72
    OD_FLAGS_RANGE = (0, 4)
    OD_INSTANCE_START_RANGE = (4, 4)
    OD_INSTANCE_SIZE_RANGE = (8, 4)
    OD_UNKNOWN_RANGE = (12, 4)
    OD_IVAR_LAYOUT_RANGE = (16, 8)
    OD_NAME_RANGE = (24, 8)
    OD_BASE_METHODS_RANGE = (32, 8)
    OD_BASE_PROTOCOLS_RANGE = (40, 8)
    OD_IVARS_RANGE = (48, 8)
    OD_WEEK_IVAR_LAYOUT_RANGE = (56, 8)
    OD_BASE_PROPERTIES_RANGE = (64, 8)

    def __init__(self):
        self.flags = 0
        self.instance_start = 0
        self.instance_size = 0
        self.unknown = 0
        self.ivar_layout = 0
        self.name = 0
        self.base_methods = 0
        self.base_protocols = 0
        self.ivar = 0
        self.week_ivar_layout = 0
        self.base_properties = 0

    @classmethod
    def parse_from_bytes(cls, _bytes):
        od = cls
        od.flags = parse_int(_bytes[0:4])
        od.instance_start = parse_int(_bytes[4:8])
        od.instance_size = parse_int(_bytes[8:12])
        od.unknown = parse_int(_bytes[12:16])
        od.ivar_layout = parse_int(_bytes[16:24])
        od.name = parse_int(_bytes[24:32])
        od.base_methods = parse_int(_bytes[32:40])
        od.base_properties = parse_int(_bytes[40:48])
        od.ivar = parse_int(_bytes[48:56])
        od.week_ivar_layout = parse_int(_bytes[56:64])
        od.base_properties = parse_int(_bytes[64:72])
        return od

    def get_size(self):
        return ObjcData64.OD_TOTAL_SIZE


class ObjcMethodList(ObjcBase):

    OM_TOTAL_SIZE = 8
    OM_FLAGS_RANGE = (0, 4)
    OM_METHOD_COUNT_RANGE = (4, 4)

    def __init__(self):
        self.flags = 0
        self.method_count = 0

    @classmethod
    def parse_from_bytes(cls, _bytes):
        om = cls()
        om.flags = parse_int(_bytes[0:4])
        om.method_count = parse_int(_bytes[4:8])
        return om

    def get_size(self):
        return ObjcMethodList.OM_TOTAL_SIZE
