class ClassData:

    def __init__(self, name):
        self.name = name
        self.super = "NSObject"
        self.methods = []
        self.ivars = []
        self.properties = []

    def insert_method(self, method):
        if method not in self.methods:
            self.methods.append(method)

    def insert_ivar(self, ivar):
        if ivar not in self.ivars:
            self.ivars.append(ivar)


class CatData:

    def __init__(self, name):
        self.name = name
        self._class = "NSObject"
        self.instance_methods = []
        self.class_methods = []
        self.instance_properties = []

    def insert_instance_method(self, method):
        if method not in self.instance_methods:
            self.instance_methods.append(method)

    def insert_class_method(self, method):
        if method not in self.class_methods:
            self.class_methods.append(method)

    def  insert_property(self, _property):
        if _property not in self.instance_properties:
            self.instance_properties.append(_property)


class FunctionData():

    def __init__(self, name):
        self.name = name
        self.return_type = 'id'   # guess default return_type should be 'id'
        self.arguments_type = []  # empty means no argument


MethodDataTypeClass = 0
MethodDataTypeInstance = 1


class MethodData:

    def __init__(self, _class, name, type=MethodDataTypeInstance):
        self._class = _class
        self.type = type
        self.name = name
        self.return_type = 'id'   # guess default return_type should be 'id'
        self.arguments_type = []  # empty means no argument


class IvarData:

    def __init__(self, name, _type):
        self.name = name
        self._type = _type


class PropertyData:

    def __init__(self, name, _type):
        self.name = name
        self._type = _type
