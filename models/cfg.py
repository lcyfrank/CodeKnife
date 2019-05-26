from graphviz import Digraph, Graph
from json import JSONEncoder
import os

CFGNodeTypeFunction = 0
CFGNodeTypeMethod = 1
CFGNodeTypeOther = 2


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
            # print(name)
            if block.name == name:
                return block
        return None

    def describe(self):
        for block in self.all_blocks:
            block.describe()

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
                graphviz_cfg.edge(node_name, oc_block_cfg.entry.name, style="dashed")
                for block in oc_block_cfg.all_blocks:
                    if block.out:
                        graphviz_cfg.edge(block.name, node_name, style="dashed")

        for block in self.all_blocks:
            for follow in block.follow_blocks:
                # print(type(follow))
                if follow in block.follow_label:
                    graphviz_cfg.edge(block.name, follow, label=block.follow_label[follow])
                else:
                    graphviz_cfg.edge(block.name, follow)

    def view(self):
        graphviz_cfg = Digraph(self.name)
        self.graphviz_obj(graphviz_cfg)
        # print(graphviz_cfg)
        graphviz_cfg.view()

    def save_to(self, path):
        graphviz_cfg = Digraph(self.name)
        self.graphviz_obj(graphviz_cfg)
        graphviz_cfg.format = 'png'
        graphviz_cfg.render(os.path.join(path, self.name + 'gv'), view=False)

    def convert_to_dict(self):
        cfg_dict = {'name': self.name}
        cfg_dict['entry'] = self.entry.convert_to_dict()
        out_list = []
        for out_block in self.outs:
            out_list.append(out_block.convert_to_dict())
        cfg_dict['outs'] = out_list
        all_blocks = []
        for block in self.all_blocks:
            all_blocks.append(block.convert_to_dict())
        cfg_dict['all_blocks'] = all_blocks
        return cfg_dict


class CFGBlock:

    def __init__(self, name):
        self.name = name
        self.out = False  # if this block contains `ret` instruction
        self.nodes = []  # node
        self.follow_blocks = []  # the blocks follow this block (name)
        self.follow_label = {}   # the follow label {name: label}

    def add_node(self, node):
        self.nodes.append(node)

    def goto_block(self, block, label=None):
        self.follow_blocks.append(block)
        if label is not None:
            self.follow_label[block] = label

    def describe(self):
        print('======================================================')
        for i in range(len(self.nodes) - 1):
            self.nodes[i].describe()
            print('||')
            print('\/')
        if len(self.nodes) > 0:
            self.nodes[-1].describe()

    def convert_to_dict(self):
        print(self.follow_label)
        cfg_block_dict = {'name': self.name, 'out': self.out,
                          'follow_blocks': self.follow_blocks, 'follow_label': self.follow_label}
        node_list = []
        for node in self.nodes:
            node_list.append(node.convert_to_dict())
        cfg_block_dict['nodes'] = node_list
        return cfg_block_dict


class CFGNode:

    def __init__(self, type):
        self.type = type
        self.class_name = ''
        self.method_name = ''
        self.function_name = ''
        self.other_str = ''
        self.oc_blocks = []

    def node_info(self):
        if self.type == CFGNodeTypeFunction:
            return self.function_name
        elif self.type == CFGNodeTypeMethod:
            return self.class_name, self.method_name
        else:
            return self.other_str

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

    def convert_to_dict(self):
        node_dict = {'type': self.type, 'class_name': self.class_name, 'method_name': self.method_name,
                     'function_name': self.function_name, 'other_str': self.other_str}
        oc_block_list = []
        for oc_block in self.oc_blocks:
            oc_block_list.append(oc_block.convert_to_dict())
        node_dict['oc_blocks'] = oc_block_list
        return node_dict

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
