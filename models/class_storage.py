class ClassData():

    def __init__(self, name):
        self.name = name
        self.super = "NSObject"
        self.methods = []
        self.ivars = []

    def insert_method(self, method):
        if method not in self.methods:
            self.methods.append(method)

    def insert_ivar(self, ivar):
        if ivar not in self.ivars:
            self.ivars.append(ivar)


class IvarData():

    def __init__(self, name, _type):
        self.name = name
        self._type = _type