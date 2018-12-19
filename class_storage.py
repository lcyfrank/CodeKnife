class ClassStorage():

    _classes_methods = []
    _classes_supers = []

    @classmethod
    def if_exit_class(cls, class_name):
        for _class in cls._classes_methods:
            if _class.name == class_name:
                return _class
        return None

    @classmethod
    def insert_method_to_class(cls, class_name, addr, name):
        if type(addr) != str:
            addr = hex(addr)
        _class = cls.if_exit_class(class_name)
        if _class == None:
            _class = ClassWithMethods(class_name)
            cls._classes_methods.append(_class)
        _class.insert_method(addr, name)

    @classmethod
    def class_name_of_addr(cls, addr):
        for _class in cls._classes_methods:
            if _class.method_name(addr) != None:
                return _class.name
        return None

    @classmethod
    def method_name_of_addr(cls, addr):
        for _class in cls._classes_methods:
            if _class.method_name(addr) != None:
                return _class.method_name(addr)
        return None

    @classmethod
    def attach_class_to_super(cls, class_name, _super):
        for _class in cls._classes_supers:
            if _class.name == class_name and _class.super != _super:
                print("There already has %s but super is %s not %s" %
                      (class_name, _class.super, _super))
                return
            elif _class.name == class_name and _class.super != _super:
                return
        _class = ClassWithSupers(class_name, _super)
        cls._classes_supers.append(_class)

    @classmethod
    def get_super(cls, class_name):
        for _class in cls._classes_supers:
            if _class.name == class_name:
                return _class.super
        return None


class ClassWithMethods():

    def __init__(self, name):
        self.name = name
        self.methods = {}

    def insert_method(self, addr, name):
        self.methods[addr] = name

    def method_name(self, addr):
        if addr in self.methods:
            return self.methods[addr]
        return None


class ClassWithSupers():

    def __init__(self, name, _super):
        self.name = name
        self.super = _super
