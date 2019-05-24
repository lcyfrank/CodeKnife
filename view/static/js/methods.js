function draw_graph() {
    console.log('sdlkfjdsklfjkldsjfklsd');
    const GO = go.GraphObject.make;
    const graph = GO(go.Diagram, 'methods-cfgs');
    graph.allowDelete = false;

    function nodeStyle() {
        return [
            new go.Binding('location', 'loc', go.Point.parse).makeTwoWay(go.Point.stringify),
            {
                locationSpot: go.Spot.Center
            }
        ];
    }

    function textStyle() {
        return {
            font: "10pt Menlo, Monaco, Consolas, sans-serif",
        }
    }

    graph.nodeTemplateMap.add('',
        GO(go.Node, 'Table', nodeStyle(),
            GO(go.Panel, 'Auto',
                GO(go.Shape, 'Rectangle',
                    {fill: 'white'},
                    new go.Binding('figure', 'figure')),
                GO(go.TextBlock, textStyle(),
                    {
                        margin: 8,
                        // maxSize: new go.Size(160, NaN),
                        wrap: go.TextBlock.WrapFit,
                        editable: true
                    },
                    new go.Binding('text').makeTwoWay())
            )
        ));

    graph.linkTemplate =
        GO(go.Link,
            {
                routing: go.Link.AvoidsNodes,
                curve: go.Link.JumpOver,
                corner: 5, toShortLength: 4,
                relinkableFrom: true,
                relinkableTo: true,
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
                new go.Binding('stroke', 'isSelected', function (sel) {
                    return sel ? "dodgerblue" : "gray";
                }).ofObject()),
            GO(go.Shape,
                {toArrow: "standard", strokeWidth: 0, fill: "gray"}),
            GO(go.Panel, 'Auto',
                {visible: false, name: "LABEL", segmentIndex: 2, segmentFraction: 0.5},
                new go.Binding('visible', 'visible').makeTwoWay(),
                GO(go.Shape, 'RoundedRectangle',
                    {fill: '#f8f8f8', strokeWidth: 0}),
                GO(go.TextBlock, 'Yes',
                    {
                        textAlign: 'center',
                        font: '10pt helvetica, arial, sans-serif',
                        stroke: '#333333',
                        editable: true
                    },
                    new go.Binding('text').makeTwoWay())
            )
        );

    cfg_model = JSON.parse(cfg_model);
    console.log(cfg_model);

    var block_pair = new Array();
    var block_level = new Array();
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
                    current_set.add(name);
                    block_level[follow].push(current_set);
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
    }
    console.log(level);

    graph.toolManager.linkingTool.temporaryLink.routing = go.Link.Orthogonal;
    graph.toolManager.relinkingTool.temporaryLink.routing = go.Link.Orthogonal;

    var nodeDataArray = [];

    for (var level_number in level) {
        for (var level_block in level[level_number]) {
            var block_name = level[level_number][level_block];
            console.log(block_name);
            var block = block_pair[block_name];

            var node_label = '';
            for (var node_index in block.nodes) {
                var node = block.nodes[node_index];
                if (node.type == 0) {
                    node_label = node_label + node.function_name;
                    node_label = node_label + '\n';
                } else {
                    node_label = node_label + node.class_name + ': ' + node.method_name;
                    node_label = node_label + '\n';
                }
            }
            if (node_label.length === 0) {
                node_label = '{NON_API_CALLED}';
            }
            nodeDataArray.push({
                key: block_name,
                loc: '175 ' + level_number * 100,
                text: node_label
            });
        }
    }

    var linkDataArray = [];
    for (var block_index in cfg_model.all_blocks) {
        var block = cfg_model.all_blocks[block_index];
        for (var follow_index in block.follow_blocks) {
            var follow = block.follow_blocks[follow_index];
            linkDataArray.push({
                from: block.name,
                to: follow,
                fromPort: 'B',
                toPort: 'T'
            });
        }
    }

    graph.model = GO(go.GraphLinksModel);
    graph.model.nodeDataArray = nodeDataArray;
    graph.model.linkDataArray = linkDataArray;

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
        draw_graph();
        $('.methods-detail-graph').hide();
        $('input[type=radio][name=options]').change(function () {
            if (this.id == 'methods-text') {
                $('.methods-detail-text').show();
                $('.methods-detail-graph').hide();
            } else {
                $('.methods-detail-text').hide();
                $('.methods-detail-graph').show();
            }
        });
    }
    $('.methods-class-selector').change(function () {
        var select = $('.methods-class-selector')[0].value;
        if (select.length > 0) {
            location.href = './methods?sel=' + select;
        } else {
            location.href = './methods';
        }
    });
});