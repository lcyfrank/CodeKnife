var graph = null;

function init_graph() {
    const GO = go.GraphObject.make;
    graph = GO(go.Diagram, 'methods-cfgs', {
        // "LinkDrawn": showLinkLabel,
        // "LinkRelinked": showLinkLabel
    });
    graph.allowDelete = false;

    function nodeStyle() {
        return [
            new go.Binding('location', 'loc', go.Point.parse).makeTwoWay(go.Point.stringify),
            {
                locationSpot: go.Spot.Center
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

    function textStyle() {
        return {
            font: "11px Helvetica, Arial, sans-serif",
            stroke: "black"
        }
    }

    graph.nodeTemplateMap.add('',
        GO(go.Node, 'Table', nodeStyle(),
            GO(go.Panel, 'Auto',
                GO(go.Shape, 'Rectangle',
                    {fill: 'white', strokeWidth: 1},
                    new go.Binding('figure', 'figure')),
                GO(go.TextBlock, textStyle(),
                    {
                        margin: 8,
                        // maxSize: new go.Size(160, NaN),
                        wrap: go.TextBlock.WrapFit,
                        editable: false
                    },
                    new go.Binding('text').makeTwoWay())
            ),

            makePort("T", go.Spot.Top, go.Spot.TopSide, false, true),
            makePort("L", go.Spot.Left, go.Spot.LeftSide, true, true),
            makePort("R", go.Spot.Right, go.Spot.RightSide, true, true),
            makePort("B", go.Spot.Bottom, go.Spot.BottomSide, true, false)
        ));

    graph.linkTemplate =
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

function draw_graph(all) {

    if (graph == null) {
        init_graph();
        cfg_model = JSON.parse(cfg_model);

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

    var modelJson = {};
    modelJson['class'] = 'go.GraphLinksModel';
    modelJson['linkFromPortIdProperty'] = 'fromPort';
    modelJson['linkToPortIdProperty'] = 'toPort';
    var nodeDataArray = [];
    var linkDataArray = [];

    var graph_total_width = 500;
    var line_height = 12;

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

            for (var node_index in block.nodes) {
                var node = block.nodes[node_index];
                if (node.type === 0) {
                    if (node_label != 0) {
                        node_label = node_label + '\n';
                    }
                    total_height += line_height;
                    node_label = node_label + node.function_name;
                } else if (node.type == 1) {
                    if (node_label != 0) {
                        node_label = node_label + '\n';
                    }
                    total_height += line_height;
                    node_label = node_label + '[' + node.class_name + ' ' + node.method_name + ']';
                } else if (all) {
                    if (node_label != 0) {
                        node_label = node_label + '\n';
                    }
                    total_height += line_height;
                    node_label = node_label + node.other_str;
                }

                for (var oc_block_index in node.oc_blocks) {
                    oc_block_cfgs.push(node.oc_blocks[oc_block_index])
                }
            }
            if (node_label.length === 0) {
                node_label = '{NON_API_CALLED}';
                total_height = 20 + line_height;
            }
            node_label = 'Name: ' + block_name + '\n\n' + node_label;
            total_height += line_height * 2;

            for (var oc_block_cfg_index in oc_block_cfgs) {
                var oc_block_cfg = oc_block_cfgs[oc_block_cfg_index];
                console.log(oc_block_cfg);
                nodeDataArray.push({
                    key: oc_block_cfg.name,
                    loc: '' + (each_width / 2 + each_width * level_block - 200) + ' ' + (current_height + (oc_block_cfg_index - oc_block_cfgs.length / 2) * 10),
                    text: oc_block_cfg.name
                });
                linkDataArray.push({
                    from: block_name, to: oc_block_cfg.name, fromPort: 'L', toPort: 'R',
                    color: 'rgba(230, 100, 20, 50)', dash: [3, 2], visible: true, text: 'OC Block'
                })
            }

            if (total_height > line_max_height) line_max_height = total_height;
            current_height += (line_max_height + 20) / 2;
            console.log('height');
            console.log(line_max_height);
            console.log(current_height);
            nodeDataArray.push({
                key: block_name,
                loc: '' + (each_width / 2 + each_width * level_block) + ' ' + current_height,
                text: node_label,
                title: block_name
            });
        }
        current_height += (line_max_height + 20) / 2;
    }
    modelJson['nodeDataArray'] = nodeDataArray;
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

            linkDataArray.push(linkData);

        }
    }
    modelJson['linkDataArray'] = linkDataArray;

    graph.model = go.Model.fromJson(JSON.stringify(modelJson));
    // graph.model = go.Model.fromJson(
    //     '{ "class": "go.GraphLinksModel",\n' +
    //     '  "linkFromPortIdProperty": "fromPort",\n' +
    //     '  "linkToPortIdProperty": "toPort",\n' +
    //     '  "nodeDataArray": [\n' +
    //     '{"key":-1, "loc":"175 0", "text":"Start"},\n' +
    //     '{"key":0, "loc":"-5 75", "text":"Preheat oven to 375 F"},\n' +
    //     '{"key":1, "loc":"175 100", "text":"In a bowl, blend: 1 cup margarine, 1.5 teaspoon vanilla, 1 teaspoon salt"},\n' +
    //     '{"key":2, "loc":"175 200", "text":"Gradually beat in 1 cup sugar and 2 cups sifted flour"},\n' +
    //     '{"key":3, "loc":"175 290", "text":"Mix in 6 oz (1 cup) Nestle\'s Semi-Sweet Chocolate Morsels"},\n' +
    //     '{"key":4, "loc":"175 380", "text":"Press evenly into ungreased 15x10x1 pan"},\n' +
    //     '{"key":5, "loc":"355 85", "text":"Finely chop 1/2 cup of your choice of nuts"},\n' +
    //     '{"key":6, "loc":"175 450", "text":"Sprinkle nuts on top"},\n' +
    //     '{"key":7, "loc":"175 515", "text":"Bake for 25 minutes and let cool"},\n' +
    //     '{"key":8, "loc":"175 585", "text":"Cut into rectangular grid"},\n' +
    //     '{"key":-2, "category":"End", "loc":"175 660", "text":"Enjoy!"}\n' +
    //     ' ],\n' +
    //     '  "linkDataArray": [\n' +
    //     '{"from":1, "to":2, "fromPort":"B", "toPort":"T", "visible": "true", "text": "test"},\n' +
    //     '{"from":2, "to":3, "fromPort":"B", "toPort":"T"},\n' +
    //     '{"from":3, "to":4, "fromPort":"B", "toPort":"T"},\n' +
    //     '{"from":4, "to":6, "fromPort":"B", "toPort":"T"},\n' +
    //     '{"from":6, "to":7, "fromPort":"B", "toPort":"T"},\n' +
    //     '{"from":7, "to":8, "fromPort":"B", "toPort":"T"},\n' +
    //     '{"from":8, "to":-2, "fromPort":"B", "toPort":"T"},\n' +
    //     '{"from":-1, "to":0, "fromPort":"B", "toPort":"T"},\n' +
    //     '{"from":-1, "to":1, "fromPort":"B", "toPort":"T"},\n' +
    //     '{"from":-1, "to":5, "fromPort":"B", "toPort":"T"},\n' +
    //     '{"from":5, "to":4, "fromPort":"B", "toPort":"T"},\n' +
    //     '{"from":0, "to":4, "fromPort":"B", "toPort":"T"}\n' +
    //     ' ]}'
    // );

// cfg_model = JSON.parse(cfg_model);
// var nodeDataArray = [];
//
// for (var block_index in cfg_model.all_blocks) {
//     var block = cfg_model.all_blocks[block_index];
//     var node_name = block.name;
//     console.log(node_name);
//
//     var node_label = '';
//     for (var node_index in block.nodes) {
//         var node = block.nodes[node_index];
//         if (node.type == 0) {
//             node_label = node_label + node.function_name;
//             node_label = node_label + '\n';
//         } else {
//             node_label = node_label + node.class_name + ': ' + node.method_name;
//             node_label = node_label + '\n';
//         }
//     }
//     if (node_label.length === 0) {
//         node_label = '{NON_API_CALLED}';
//     }
//     nodeDataArray.push({
//         key: node_name,
//         content: node_label
//     });
// }
//
// var model = GO(go.GraphLinksModel);
// model.nodeDataArray = nodeDataArray;
//
// var linkDataArray = [];
// for (var block_index in cfg_model.all_blocks) {
//     var block = cfg_model.all_blocks[block_index];
//     for (var follow_index in block.follow_blocks) {
//         var follow = block.follow_blocks[follow_index];
//         linkDataArray.push({from: block.name, to: follow})
//     }
// }
// model.linkDataArray = linkDataArray;
// graph.model = model;
}

$(function () {
    if (cfg_model != 'null') {
        draw_graph(false);
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
        draw_graph(this.checked);
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