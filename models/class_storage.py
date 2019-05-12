class ClassData:

    def __init__(self, name=None, cd_dict=None):
        if cd_dict is None:
            self.name = name
            self.super = "NSObject"
            self.methods = []
            self.ivars = []
            self.properties = []
        else:
            self.name = cd_dict['name']
            self.super = cd_dict['super']
            self.methods = cd_dict['methods']
            self.ivars = []
            self.properties = []
            for ivar_dict in cd_dict['ivars']:
                ivar = IvarData(id_dict=ivar_dict)
                self.ivars.append(ivar)
            for property_dict in cd_dict['properties']:
                property_data = PropertyData(pd_dict=property_dict)
                self.properties.append(property_data)

    def insert_method(self, method):
        if method not in self.methods:
            self.methods.append(method)

    def insert_ivar(self, ivar):
        if ivar not in self.ivars:
            self.ivars.append(ivar)

    def insert_property(self, _property):
        if _property not in self.properties:
            self.properties.append(_property)

    def convert_to_dict(self):
        cd_dict = self.__dict__.copy()
        cd_dict['ivars'] = []
        cd_dict['properties'] = []
        for ivar in self.ivars:
            cd_dict['ivars'].append(ivar.convert_to_dict())
        for property in self.properties:
            cd_dict['properties'].append(property.convert_to_dict())
        return cd_dict


class CatData:

    def __init__(self, name=None, cd_dict=None):
        if cd_dict is None:
            self.name = name
            self._class = "NSObject"
            self.instance_methods = []
            self.class_methods = []
            self.instance_properties = []
        else:
            self.name = cd_dict['name']
            self._class = cd_dict['_class']
            self.instance_methods = cd_dict['instance_methods']
            self.class_methods = cd_dict['class_methods']
            self.instance_properties = []
            for property_dict in cd_dict['instance_properties']:
                self.instance_properties.append(PropertyData(pd_dict=property_dict))

    def insert_instance_method(self, method):
        if method not in self.instance_methods:
            self.instance_methods.append(method)

    def insert_class_method(self, method):
        if method not in self.class_methods:
            self.class_methods.append(method)

    def insert_property(self, _property):
        if _property not in self.instance_properties:
            self.instance_properties.append(_property)

    def convert_to_dict(self):
        cd_dict = self.__dict__.copy()
        cd_dict['instance_properties'] = []
        for property in self.instance_properties:
            cd_dict['instance_properties'].append(property.convert_to_dict())
        return cd_dict


class FunctionData():

    def __init__(self, name=None, fd_dict=None):
        if fd_dict is None:
            self.name = name
            self.return_type = 'id'   # guess default return_type should be 'id'
            self.arguments_type = []  # empty means no argument
        else:
            self.name = fd_dict['name']
            self.return_type = fd_dict['return_type']
            self.arguments_type = []
            for argument_type_dict in fd_dict['arguments_type']:
                self.arguments_type.append(ArgumentData(argument_type_dict))

    def convert_to_dict(self):
        return self.__dict__.copy()


BlockMethodTypeStack = 0
BlockMethodTypeGlobal = 1
BlockMethodTypeMalloc = 2


class BlockMethodData:

    def __init__(self, type=BlockMethodTypeStack, bmd_dict=None):
        if bmd_dict is None:
            self.type = type
            self.invoke = 0
        else:
            self.type = bmd_dict['type']
            self.invoke = bmd_dict['invoke']

    def convert_to_dict(self):
        return self.__dict__.copy()


class ArgumentData:

    def __init__(self, type=None, length=None, ad_dict=None):
        if ad_dict is None:
            self.type = type
            self.length = length
        else:
            self.type = ad_dict['type']
            self.length = ad_dict['length']

    def convert_to_dict(self):
        return self.__dict__.copy()


MethodDataTypeClass = 0
MethodDataTypeInstance = 1


class MethodData:

    def __init__(self, _class=None, name=None, type=MethodDataTypeInstance, md_dict=None):
        if md_dict is None:
            self._class = _class
            self.type = type
            self.name = name
            self.return_type = 'id'   # guess default return_type should be 'id'
            self.arguments_type = []  # empty means no argument
        else:
            self._class = md_dict['_class']
            self.type = md_dict['type']
            self.name = md_dict['name']
            self.return_type = md_dict['return_type']
            self.arguments_type = []
            for argument_type_dict in md_dict['arguments_type']:
                self.arguments_type.append(ArgumentData(argument_type_dict))

    def convert_to_dict(self):
        md_dict = self.__dict__.copy()
        md_dict['arguments_type'] = []
        for argument_type in self.arguments_type:
            md_dict['arguments_type'].append(argument_type.convert_to_dict())
        return md_dict


class IvarData:

    def __init__(self, name=None, _type=None, id_dict=None):
        if id_dict is None:
            self.name = name
            self._type = _type
        else:
            self.name = id_dict['name']
            self._type = id_dict['_type']

    def convert_to_dict(self):
        return self.__dict__.copy()


class PropertyData:

    def __init__(self, name=None, _type=None, pd_dict=None):
        if pd_dict is None:
            self.name = name
            self._type = _type
        else:
            self.name = pd_dict['name']
            self._type = pd_dict['_type']

    def convert_to_dict(self):
        return self.__dict__.copy()
