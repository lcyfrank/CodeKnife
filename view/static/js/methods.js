var cfg_graph = null;
var dfg_graph = null;

function init_graph() {
    const GO = go.GraphObject.make;
    cfg_graph = GO(go.Diagram, 'methods-cfgs', {});
    cfg_graph.allowDelete = false;

    dfg_graph = GO(go.Diagram, 'methods-dfgs', {});
    dfg_graph.allowDelete = false;

    function cfg_nodeStyle() {
        return [
            new go.Binding('location', 'loc', go.Point.parse).makeTwoWay(go.Point.stringify),
            {
                locationSpot: go.Spot.Center,
                isShadowed: true,
                shadowColor: "#C5C1AA",
            }
        ];
    }

    function dfg_nodeStyle() {
        return [
            new go.Binding('location', 'loc', go.Point.parse).makeTwoWay(go.Point.stringify),
            {
                locationSpot: go.Spot.Center,
            }
        ];
    }

    function makePort(name, align, spot, output, input) {
        var horizontal = align.equals(go.Spot.Top) || align.equals(go.Spot.Bottom);
        // the port is basically just a transparent rectangle that stretches along the side of the node,
        // and becomes colored when the mouse passes over it
        return GO(go.Shape,
            {
                fill: "transparent",  // changed to a color in the mouseEnter event handler
                strokeWidth: 0,  // no stroke
                width: horizontal ? NaN : 0,  // if not stretching horizontally, just 8 wide
                height: !horizontal ? NaN : 0,  // if not stretching vertically, just 8 tall
                alignment: align,  // align the port on the main Shape
                stretch: (horizontal ? go.GraphObject.Horizontal : go.GraphObject.Vertical),
                portId: name,  // declare this object to be a "port"
                fromSpot: spot,  // declare where links may connect at this port
                fromLinkable: output,  // declare whether the user may draw links from here
                toSpot: spot,  // declare where links may connect at this port
                toLinkable: input,  // declare whether the user may draw links to here
                // cursor: "pointer",  // show a different cursor to indicate potential link point
                mouseEnter: function (e, port) {  // the PORT argument will be this Shape
                },
                mouseLeave: function (e, port) {
                }
            });
    }

    var itemTempl = GO(go.Panel, "Horizontal",
        GO(go.TextBlock,
            {
                stroke: "black",
                font: "11px Menlo, Monaco, Consolas, 'Andale Mono', 'lucida console', 'Courier New', monospace",
                margin: new go.Margin(3, 0, 3, 0)
            },
            new go.Binding("text", "text"),
            new go.Binding('stroke', 'color'),
            new go.Binding('visible', 'normal')),
        GO(go.TextBlock,
            {
                stroke: "black",
                font: "bold 11px Menlo, Monaco, Consolas, 'Andale Mono', 'lucida console', 'Courier New', monospace",
                desiredSize: new go.Size(50, 15),
                visible: false
            },
            new go.Binding("text", "instruction"),
            new go.Binding('visible', 'code')),
        GO(go.TextBlock,
            {
                stroke: "#3F7FEE",
                font: "11px Menlo, Monaco, Consolas, 'Andale Mono', 'lucida console', 'Courier New', monospace",
                visible: false
            },
            new go.Binding("text", "operands"),
            new go.Binding('visible', 'code'))
    );

    cfg_graph.nodeTemplateMap.add('',
        GO(go.Node, 'Table', cfg_nodeStyle(),
            GO(go.Panel, 'Auto',
                GO(go.Shape, 'Rectangle',
                    {fill: 'white', strokeWidth: 1},
                    new go.Binding('figure', 'figure')),
                GO(go.Panel, 'Vertical',
                    {
                        row: 1,
                        padding: 8,
                        alignment: go.Spot.TopLeft,
                        defaultAlignment: go.Spot.Left,
                        stretch: go.GraphObject.Horizontal,
                        itemTemplate: itemTempl
                    },
                    new go.Binding('itemArray', 'items'))
            ),

            makePort("T", go.Spot.Top, go.Spot.TopSide, false, true),
            makePort("L", go.Spot.Left, go.Spot.LeftSide, true, true),
            makePort("R", go.Spot.Right, go.Spot.RightSide, true, true),
            makePort("B", go.Spot.Bottom, go.Spot.BottomSide, true, false)
        ));
    dfg_graph.nodeTemplateMap.add('',
        GO(go.Node, 'Table', dfg_nodeStyle(),
            GO(go.Panel, 'Auto',
                GO(go.Shape, 'Rectangle',
                    {fill: 'white', strokeWidth: 1},
                    new go.Binding('figure', 'figure')),
                GO(go.Panel, 'Vertical',
                    {
                        row: 1,
                        padding: 8,
                        alignment: go.Spot.TopLeft,
                        defaultAlignment: go.Spot.Left,
                        stretch: go.GraphObject.Horizontal,
                        itemTemplate: itemTempl
                    },
                    new go.Binding('itemArray', 'items'))
            ),

            makePort("T", go.Spot.Top, go.Spot.TopSide, false, true),
            makePort("L", go.Spot.Left, go.Spot.LeftSide, true, true),
            makePort("R", go.Spot.Right, go.Spot.RightSide, true, true),
            makePort("B", go.Spot.Bottom, go.Spot.BottomSide, true, false)
        ));

    cfg_graph.linkTemplate =
        GO(go.Link,
            {
                routing: go.Link.AvoidsNodes,
                curve: go.Link.JumpOver,
                corner: 5, toShortLength: 4,
                // relinkableFrom: true,
                // relinkableTo: true,
                reshapable: true,
                resegmentable: true,

                mouseEnter: function (e, link) {
                    link.findObject('HIGHLIGHT').stroke = 'rgba(30,144,255,0.2)';
                },
                mouseLeave: function (e, link) {
                    link.findObject('HIGHLIGHT').stroke = 'transparent';
                },
                selectionAdorned: false
            },
            new go.Binding('points').makeTwoWay(),
            GO(go.Shape,
                {isPanelMain: true, strokeWidth: 8, stroke: 'transparent', name: 'HIGHLIGHT'}),
            GO(go.Shape,
                {isPanelMain: true, stroke: "gray", strokeWidth: 2},
                new go.Binding('stroke', 'color'),
                new go.Binding('strokeDashArray', 'dash')),
            GO(go.Shape,
                {toArrow: "standard", strokeWidth: 0, fill: "gray"},
                new go.Binding('fill', 'color')),
            GO(go.Panel, 'Auto',
                {visible: false, name: "LABEL", segmentIndex: 2, segmentFraction: 0.5},
                new go.Binding('visible', 'visible').makeTwoWay(),
                GO(go.Shape, 'RoundedRectangle',
                    {fill: '#f8f8f8', strokeWidth: 0}),
                GO(go.TextBlock, 'Yes',
                    {
                        textAlign: 'center',
                        font: '10px helvetica, arial, sans-serif',
                        stroke: '#333333',
                        editable: true
                    },
                    new go.Binding('text').makeTwoWay())
            )
        );
    dfg_graph.linkTemplate =
        GO(go.Link,
            {
                routing: go.Link.AvoidsNodes,
                curve: go.Link.JumpOver,
                corner: 5, toShortLength: 4,
                // relinkableFrom: true,
                // relinkableTo: true,
                reshapable: true,
                resegmentable: true,

                mouseEnter: function (e, link) {
                    link.findObject('HIGHLIGHT').stroke = 'rgba(30,144,255,0.2)';
                },
                mouseLeave: function (e, link) {
                    link.findObject('HIGHLIGHT').stroke = 'transparent';
                },
                selectionAdorned: false
            },
            new go.Binding('points').makeTwoWay(),
            GO(go.Shape,
                {isPanelMain: true, strokeWidth: 8, stroke: 'transparent', name: 'HIGHLIGHT'}),
            GO(go.Shape,
                {isPanelMain: true, stroke: "gray", strokeWidth: 2},
                new go.Binding('stroke', 'color'),
                new go.Binding('strokeDashArray', 'dash')),
            GO(go.Shape,
                {toArrow: "standard", strokeWidth: 0, fill: "gray"},
                new go.Binding('fill', 'color')),
            GO(go.Panel, 'Auto',
                {visible: false, name: "LABEL", segmentIndex: 2, segmentFraction: 0.5},
                new go.Binding('visible', 'visible').makeTwoWay(),
                GO(go.Shape, 'RoundedRectangle',
                    {fill: '#f8f8f8', strokeWidth: 0}),
                GO(go.TextBlock, 'Yes',
                    {
                        textAlign: 'center',
                        font: '10px helvetica, arial, sans-serif',
                        stroke: '#333333',
                        editable: true
                    },
                    new go.Binding('text').makeTwoWay())
            )
        );
}

function draw_cfg_graph(all) {

    if (cfg_graph == null) {
        init_graph();
        cfg_model = JSON.parse(cfg_model);
        data_flows_model = JSON.parse(data_flows_model);
    }

    var block_pair = new Array();
    var block_level = {};
    for (var block_index in cfg_model.all_blocks) {
        var block = cfg_model.all_blocks[block_index];
        block_pair[block.name] = block;
        block_level[block.name] = new Array();
    }
    var entry_name = cfg_model.entry.name;
    block_level[entry_name] = new Array(new Set());

    var waited_names = new Array(entry_name);
    var visited_names = new Set();
    while (waited_names.length > 0) {
        var name = waited_names.shift();
        visited_names.add(name);
        for (var follow_index in block_pair[name].follow_blocks) {
            var follow = block_pair[name].follow_blocks[follow_index];
            if (!visited_names.has(follow))
                waited_names.push(follow);

            var current_sets = block_level[name];
            var should_add = true;
            for (var current_set_index in current_sets) {
                var current_set = current_sets[current_set_index];
                if (current_set.has(follow)) {
                    should_add = false;
                    break;
                }
            }

            if (should_add) {
                for (var current_set_index in current_sets) {
                    var current_set = new Set(current_sets[current_set_index]);
                    current_set.add(name);  // 将自己添加进去

                    block_level[follow].push(current_set);
                    if (waited_names.indexOf(follow) == -1)
                        waited_names.push(follow);
                }
            }
        }
    }

    var level = new Array();
    for (var block_name in block_level) {
        var maximal_level = 0;
        for (var block_paths_index in block_level[block_name]) {
            var block_paths = block_level[block_name][block_paths_index];
            if (block_paths.size > maximal_level) {
                maximal_level = block_paths.size;
            }
        }
        if (level[maximal_level] == undefined)
            level[maximal_level] = new Array();
        level[maximal_level].push(block_name);
        block_level[block_name] = maximal_level;
    }

    var cfg_modelJson = {};
    cfg_modelJson['class'] = 'go.GraphLinksModel';
    cfg_modelJson['linkFromPortIdProperty'] = 'fromPort';
    cfg_modelJson['linkToPortIdProperty'] = 'toPort';
    var cfg_nodeDataArray = [];
    var cfg_linkDataArray = [];

    var graph_total_width = 300;
    var line_height = 15;

    var current_height = 0;

    for (var level_number in level) {  // 每一行
        var block_count = level[level_number].length;
        if (block_count <= 0) continue;

        var line_max_height = 0;
        var each_width = graph_total_width / block_count;
        for (var level_block in level[level_number]) {  // 每一列
            var block_name = level[level_number][level_block];
            var block = block_pair[block_name];

            var node_label = '';
            var total_height = 20;

            var oc_block_cfgs = [];

            var node_items = [];
            for (var node_index in block.nodes) {
                var node = block.nodes[node_index];
                if (node.type === 0) {
                    if (node_label != 0) {
                        node_label = node_label + '\n';
                    }
                    total_height += line_height;
                    node_label = node_label + node.function_name;
                    if (all) {
                        node_items.push({
                            text: (node.function_name),
                            color: '#53A351',
                            normal: true
                        });
                    } else {
                        node_items.push({
                            text: (node.function_name),
                            color: 'rgba(15, 15, 15, 100)',
                            normal: true
                        });
                    }
                } else if (node.type == 1) {
                    if (node_label != 0) {
                        node_label = node_label + '\n';
                    }
                    total_height += line_height;
                    node_label = node_label + '[' + node.class_name + ' ' + node.method_name + ']';
                    if (all) {
                        node_items.push({
                            text: ('[' + node.class_name + ' ' + node.method_name + ']'),
                            color: '#53A351',
                            normal: true
                        });
                    } else {
                        node_items.push({
                            text: ('[' + node.class_name + ' ' + node.method_name + ']'),
                            color: 'rgba(15, 15, 15, 100)',
                            normal: true
                        });
                    }
                } else if (all) {
                    if (node_label != 0) {
                        node_label = node_label + '\n';
                    }
                    total_height += line_height;
                    var instruction = '';
                    var ins_fragment = node.other_str.split(' ');
                    instruction += ins_fragment[0];
                    for (var i = ins_fragment[0].length; i <= 8; ++i)
                        instruction += ' ';
                    var operands = '';
                    for (var i = 1; i < ins_fragment.length; ++i) {
                        operands += ins_fragment[i];
                    }

                    node_items.push({instruction: instruction, operands: operands, normal: false, code: true});
                }

                for (var oc_block_index in node.oc_blocks) {
                    oc_block_cfgs.push(node.oc_blocks[oc_block_index])
                }
            }
            if (node_items.length === 0) {
                total_height = 20 + line_height;
                node_items.push({text: '{NON_API_CALLED}', color: 'rgba(100, 100, 100, 100)'});
            }
            node_label = 'Name: ' + block_name + '\n\n' + node_label;
            total_height += line_height * 2;

            for (var oc_block_cfg_index in oc_block_cfgs) {
                var oc_block_cfg = oc_block_cfgs[oc_block_cfg_index];
                cfg_nodeDataArray.push({
                    key: oc_block_cfg.name,
                    loc: '' + (each_width / 2 + each_width * level_block - 200) + ' ' + (current_height + (oc_block_cfg_index - oc_block_cfgs.length / 2) * 10),
                    items: [{text: oc_block_cfg.name, color: 'rgba(100, 100, 100, 100)'}]
                });
                cfg_linkDataArray.push({
                    from: block_name, to: oc_block_cfg.name, fromPort: 'L', toPort: 'R',
                    color: 'rgba(230, 100, 20, 50)', dash: [3, 2], visible: true, text: 'OC Block'
                })
            }

            if (total_height > line_max_height) line_max_height = total_height;
            current_height += (line_max_height + 20) / 2;
            cfg_nodeDataArray.push({
                key: block_name,
                loc: '' + (each_width / 2 + each_width * level_block) + ' ' + current_height,
                items: node_items,
            });
        }
        current_height += (line_max_height + 20) / 2;
    }

    cfg_modelJson['nodeDataArray'] = cfg_nodeDataArray;
    for (var block_index in cfg_model.all_blocks) {
        var block = cfg_model.all_blocks[block_index];
        var current_level = block_level[block.name];

        for (var follow_index in block.follow_blocks) {
            var follow = block.follow_blocks[follow_index];
            var to_level = block_level[follow];
            var linkData = {from: block.name, to: follow, fromPort: 'B', toPort: 'T'};
            if (current_level >= to_level) {
                linkData.color = 'rgba(100, 120, 230, 45)';
                linkData.dash = [3, 2];
            }

            console.log(block);
            console.log(block.follow_label);

            cfg_linkDataArray.push(linkData);

        }
    }
    cfg_modelJson['linkDataArray'] = cfg_linkDataArray;
    cfg_graph.model = go.Model.fromJson(JSON.stringify(cfg_modelJson));
}

function draw_dfg_graph() {
    if (cfg_graph == null) {
        init_graph();
        cfg_model = JSON.parse(cfg_model);
        data_flows_model = JSON.parse(data_flows_model);
    }
    var dfg_modelJson = {};
    dfg_modelJson['class'] = 'go.GraphLinksModel';
    dfg_modelJson['linkFromPortIdProperty'] = 'fromPort';
    dfg_modelJson['linkToPortIdProperty'] = 'toPort';
    var dfg_nodeDataArray = [];
    var dfg_linkDataArray = [];

    var graph_total_width = 300;

    var update_data_flow_names = new Array();
    for (var df_source_name in data_flows_model) {
        update_data_flow_names.push(df_source_name);
    }

    var data_flow_pair = {};
    var data_flow_level = {};
    while (update_data_flow_names.length > 0) {
        var data_flow_name = update_data_flow_names.shift();
        var base_level = 0;
        if (data_flow_level.hasOwnProperty(data_flow_name)) {
            base_level = data_flow_level[data_flow_name];
        }
        data_flow_level[data_flow_name] = base_level;

        var data_flow = data_flows_model[data_flow_name];
        var flow_tos = data_flow.flow_to;
        for (var flow_to_index in flow_tos) {
            var flow_to = flow_tos[flow_to_index];
            var flow_to_name = '0x' + Number(flow_to[0].address).toString(16);
            data_flow_level[flow_to_name] = base_level + 1;
            data_flow_pair[flow_to_name] = flow_to;
            if (data_flows_model.hasOwnProperty(flow_to_name)) {
                update_data_flow_names.push(flow_to_name);
            }
        }
    }

    var level = new Array();
    for (var df_name in data_flow_level) {
        if (!level.hasOwnProperty(data_flow_level[df_name])) {
            level[data_flow_level[df_name]] = new Array();
        }
        level[data_flow_level[df_name]].push(df_name);
    }

    for (var level_number in level) {  // 每一行
        var df_count = level[level_number].length;
        if (df_count <= 0) continue;

        var each_width = graph_total_width / df_count;
        var current_width = 0;
        for (var df_index in level[level_number]) {  // 每一列
            var df_name = level[level_number][df_index];
            var data_flow = data_flows_model[df_name];
            if (data_flow === undefined) {
                data_flow = data_flow_pair[df_name];
                var df_text = data_flow[0];
                if (typeof data_flow[0] !== "string") {
                    df_text = '[' + data_flow[0].goto_insns + ']';
                }
                dfg_nodeDataArray.push({
                    key: 'df' + df_name,
                    loc: '' + (current_width) + ' ' + (70 * level_number),
                    items: [{text: df_text, color: 'rgba(100, 100, 100, 100)'}],
                });
                current_width += (df_text.length) * 10;
            } else {
                var df_text = df_name;
                if (typeof data_flow.source !== "string") {
                    df_text = '[' + data_flow.source.goto_insns + ']';
                }
                dfg_nodeDataArray.push({
                    key: 'df' + df_name,
                    loc: '' + (current_width) + ' ' + (70 * level_number),
                    items: [{text: df_text, color: 'rgba(100, 100, 100, 100)'}],
                });
                current_width += (df_text.length) * 10;
                for (var flow_to_index in data_flow.flow_to) {
                    var flow_to_position = data_flow.flow_to[flow_to_index];
                    var flow_to = flow_to_position[0];
                    var position = flow_to_position[1];
                    dfg_linkDataArray.push({
                        from: 'df' + df_name,
                        to: 'df0x' + Number(flow_to.address).toString(16),
                        fromPort: 'B',
                        toPort: 'T',
                        color: 'rgba(0, 0, 0, 50)',
                        visible: true,
                        text: position
                    })
                }
            }
        }
    }
    dfg_modelJson['nodeDataArray'] = dfg_nodeDataArray;
    dfg_modelJson['linkDataArray'] = dfg_linkDataArray;
    dfg_graph.model = go.Model.fromJson(JSON.stringify(dfg_modelJson));
}

$(function () {
    if (cfg_model != 'null') {
        draw_cfg_graph(false);
        draw_dfg_graph();
    }
    $('input[type=radio][name=options]').change(function () {
        if (this.id == 'methods-text') {
            $('.methods-detail-text').show();
            $('.methods-detail-graph').hide();
            $('.methods-show-all').hide();
        } else {
            $('.methods-detail-text').hide();
            $('.methods-detail-graph').show();
            $('.methods-show-all').show();
        }
    });

    $('.methods-show-all').find('input').change(function () {
        draw_cfg_graph(this.checked);
    });

    $('.methods-class-selector').change(function () {

        var query = window.location.search.substring(1);
        var vars = query.split("&");
        var address_str = ''
        for (var i in vars) {
            var pair = vars[i].split("=");
            if (pair[0] == 'address') {
                address_str = 'address=' + pair[1];
            }
        }
        var select = $('.methods-class-selector')[0].value;
        if (select.length > 0) {
            var url = './methods?sel=' + select;
            if (address_str.length > 0) {
                url += '&';
                url += address_str
            }
            location.href = url;
        } else {
            var url = './methods' + select;
            if (address_str.length > 0) {
                url += '?';
                url += address_str
            }
            location.href = url;
        }
    });
});