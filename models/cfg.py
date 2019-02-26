from graphviz import Digraph, Graph

CFGNodeTypeFunction = 0
CFGNodeTypeMethod = 1


class CFG:

    def __init__(self, name='', entry=None):
        self.name = name
        self.entry = entry
        self.outs = []
        self.all_blocks = []

    def add_block(self, block):
        self.all_blocks.append(block)
        if block.out:
            self.outs.append(block)

    def get_block(self, name):
        for block in self.all_blocks:
            if block.name == name:
                return block
        return None
    # if the data flow between the no.0 node and no.1 node
    # the index should be 0
    # def modify_data_flow(self, index, data_flow):
    #     node_count = len(self.nodes)
    #     if node_count - 1 > index:
    #         if index < len(self.data_flows):
    #             self.data_flows[index] = data_flow
    #         else:
    #             for i in range(index):
    #                 self.data_flows.append(None)
    #             self.data_flows.append(data_flow)
    #     else:
            # print('Data flow index error!')

    def describe(self):
        for block in self.all_blocks:
            block.describe()

    # def graphviz_block(self, block, graphviz_cfg):
    #
    #     oc_block_cfgs = []
    #     node_name = block.name
    #     node_label = ''
    #     for node in block.nodes:
    #         node_label += node.describe(False)[1:-1]
    #         node_label += '\n'
    #         for oc_block_cfg in node.oc_blocks:
    #             oc_block_cfgs.append(oc_block_cfg)
    #     if len(node_label) == 0:
    #         node_label = '{NON_API_CALLED}'
    #     graphviz_cfg.node(node_name, node_label, shape='box')
    #
    #     for oc_block_cfg in oc_block_cfgs:
    #         for block in oc_block_cfg.all_blocks:
    #             if block == oc_block_cfg.entry:


        # return node_name

    def graphviz_obj(self, graphviz_cfg):
        # print(len(self.all_blocks))
        for block in self.all_blocks:

            oc_block_cfgs = []

            node_name = block.name
            node_label = ''
            for node in block.nodes:
                # node_name = block.name + str(block.nodes.index(node))
                node_label += node.describe(False)[1:-1]
                node_label += '\n'
                for oc_block_cfg in node.oc_blocks:
                    oc_block_cfgs.append(oc_block_cfg)
                # cfg_view.node(node_name, node_label)
            if len(node_label) == 0:
                node_label = '{NON_API_CALLED}'
            graphviz_cfg.node(node_name, node_label, shape='box')

            for oc_block_cfg in oc_block_cfgs:
                oc_block_cfg.graphviz_obj(graphviz_cfg)
                graphviz_cfg.edge(node_name, oc_block_cfg.entry.name)
                for block in oc_block_cfg.all_blocks:
                    if block.out:
                        print('dsafjshfkjhsdjklfhdasjklhfjklsdhfjkdsahfjksh')
                        graphviz_cfg.edge(block.name, node_name)

        for block in self.all_blocks:
            for follow in block.follow_blocks:
                # print(type(follow))
                graphviz_cfg.edge(block.name, follow)

        # return graphviz_cfg

        # block_nodes = {}
        # cfg_view = Digraph(self.name)
        # # cfg_view.node('entry', 'entry')
        #
        # for block in self.all_blocks:
        #     block_view = Digraph('cluster' + block.name)
        #     if len(block.nodes) == 0:
        #         node_name = 'node' + block.name
        #         block_view.node(node_name, '', shape='plaintext')
        #         block_nodes[block.name] = (node_name, node_name)
        #     else:
        #         start_name = None
        #         end_name = None
        #         before_name = None
        #         for node in block.nodes:
        #             if type(node) == CFG:
        #                 pass
        #                 # recursive_cfg = node.graphviz_obj()
        #                 # block_view.subgraph(recursive_cfg)
        #
        #             elif type(node) == CFGNode:
        #                 node_name = block.name + str(block.nodes.index(node))
        #                 node_label = node.describe(False)
        #                 block_view.node(node_name, node_label, shape='box')
        #                 if before_name is not None:
        #                     block_view.edge(before_name, node_name)
        #                 before_name = node_name
        #                 if start_name is None:
        #                     start_name = node_name
        #                 if block == self.all_blocks[-1]:
        #                     end_name = end_name
        #         block_nodes[block.name] = (start_name, end_name)
        #
        #     cfg_view.subgraph(block_view)
        #
        # # cfg_view.edge('entry', 'cluster' + self.entry.name)
        #
        # for block in self.all_blocks:
        #     _, first_name = block_nodes[block.name]
        #     for follow in block.follow_blocks:
        #         second_name, _ = block_nodes[follow]
        #         cfg_view.edge(first_name, second_name)
        # return cfg_view

    def view(self):
        graphviz_cfg = Digraph(self.name)
        self.graphviz_obj(graphviz_cfg)
        graphviz_cfg.view()

class CFGBlock:

    def __init__(self, name):
        self.name = name
        self.out = False  # if this block contains `ret` instruction
        self.nodes = []  # node 包括 node 或者 cfg
        self.follow_blocks = []  # the blocks follow this block (name)

    def add_node(self, node):
        self.nodes.append(node)

    def goto_block(self, block):
        self.follow_blocks.append(block)

    def describe(self):
        print('======================================================')
        for i in range(len(self.nodes) - 1):
            self.nodes[i].describe()
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
        self.oc_blocks = []

    def node_info(self):
        if self.type == CFGNodeTypeFunction:
            return self.function_name
        else:
            return self.class_name, self.method_name

    def describe(self, verbose=True):
        if self.type == CFGNodeTypeFunction:
            if verbose:
                print('<%s>' % self.function_name)
            describe = '<' + self.function_name + '>'
        else:
            if verbose:
                print('<%s: %s>' % (self.class_name, self.method_name))
            describe = '<' + self.class_name + ': ' + self.method_name + '>'
        return describe


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
