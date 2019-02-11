CFGNodeTypeFunction = 0
CFGNodeTypeMethod = 1


class CFG:

    def __init__(self, name=''):
        self.name = name
        self.nodes = []
        self.data_flows = []

    def add_node(self, node):
        self.nodes.append(node)

    # if the data flow between the no.0 node and no.1 node
    # the index should be 0
    def modify_data_flow(self, index, data_flow):
        node_count = len(self.nodes)
        if node_count - 1 > index:
            if index < len(self.data_flows):
                self.data_flows[index] = data_flow
            else:
                for i in range(index):
                    self.data_flows.append(None)
                self.data_flows.append(data_flow)
        else:
            print('Data flow index error!')

    def describe(self):
        for i in range(1, len(self.nodes) - 1):
            self.nodes[i].describe()
            if (i - 1 < len(self.data_flows) and
                self.data_flows[i - 1] is not None and
                not self.data_flows[i - 1].isEmpty):
                self.data_flows[i - 1].describe()
            else:
                print('||')
                print('\/')
        if len(self.nodes) > 0:
            self.nodes[-1].describe()


class CFGNode:

    def __init__(self, type):
        self.type = type
        self.class_name = ''
        self.method_name = ''
        self.function_name = ''

    def node_info(self):
        if self.type == CFGNodeTypeFunction:
            return self.function_name
        else:
            return self.class_name, self.method_name

    def describe(self):
        if self.type == CFGNodeTypeFunction:
            print('<%s>' % self.function_name)
        else:
            print('<%s: %s>' % (self.class_name, self.method_name))


class CFGDataFlow:

    def __init__(self, identify=''):
        self.identify = identify
        self.types = []

    def is_empty(self):
        return len(self.types) == 0

    def add_type(self, type):
        self.types.append(type)

    def describe(self):
        for i in range(len(self.types)):
            print('|| (%s)' % self.types[i])
        print('\/')
