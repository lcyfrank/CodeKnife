class ClassData():

    def __init__(self, name):
        self.name = name
        self.super = "NSObject"
        self.methods = []

    def insert_method(self, method):
        if method not in self.methods:
            self.methods.append(method)