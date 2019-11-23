$(function () {

    var codeArea = $('.code-editor')[0];
    var name_input = $('.editor-file-name')[0];

    var editor = CodeMirror.fromTextArea(codeArea, {
        lineNumbers: true,
        mode: 'python',
        theme: 'material'
    });

    editor.on('change', () => {
        $('.editor-delete-button')[0].disabled = true;

        if ($('.editor-save-button')[0].disabled === true && name_input.value.length > 0)
            $('.editor-save-button')[0].disabled = false;
        codeArea.innerHTML = editor.getValue();
    });

    name_input.addEventListener('input', () => {
        $('.editor-delete-button')[0].disabled = true;
        var name_length = name_input['value'].length;
        if (name_length > 0) {
            if ($('.editor-save-button')[0].disabled === true)
                $('.editor-save-button')[0].disabled = false;
        } else {
            $('.editor-save-button')[0].disabled = true;
        }

    });

    var save_button = $('.editor-save-button')[0];
    save_button.addEventListener('click', save_button_click);

    var delete_button = $('.editor-delete-button')[0];
    delete_button.addEventListener('click', delete_button_click);
});

function convert_to_str(msg) {
    if (msg instanceof Array) {
        var msg_str = '[';
        for (var msg_item_index in msg) {
            var msg_item = msg[msg_item_index];
            if (msg_item_index > 0) {
                msg_str += ', ';
            }
            msg_str += msg_item;
        }
        msg_str += ']';
        return msg_str;
    } else if (msg instanceof Object) {
        var msg_str = '{';
        var index = 0;
        for (var msg_item_key in msg) {
            var msg_item = msg[msg_item_key];
            if (index > 0) {
                msg_str += ', ';
            }
            msg_str += msg_item_key + ': ' + msg_item;
            index += 1;
        }
        return msg_str;
    } else {
        return msg;
    }
}

function execute_code() {
    var codeArea = $('.code-editor')[0];

    $.ajax({
        type: 'POST',
        url: '/analysis/binary/' + file_md5 + '/execute',
        data: codeArea.innerHTML,
        success: function (data) {
            if (data === 'OK') {
                $('.checker-result')[0].innerHTML = '';
                var msg_request = setInterval(function () {
                    $.ajaxSettings.async = false;
                    $.getJSON("/analysis/binary/" + file_md5 + "/execute/status", function (result) {
                        console.log(result);
                        if (result['type'] == 0) {
                            var msg = result['msg'];
                            var old_data = $('.checker-result')[0].innerHTML;
                            var new_data = old_data + '<p class="checker-result-success"><span>[+] </span>' + msg + '</p>';
                            $('.checker-result')[0].innerHTML = new_data;
                        } else if (result['type'] == -1) {
                            var msg = result['msg'];
                            var old_data = $('.checker-result')[0].innerHTML;
                            var new_data = old_data + '<p class="checker-result-error"><span>[-] </span>' + msg + '</p>';
                            $('.checker-result')[0].innerHTML = new_data;
                        } else {
                            var msg = result['msg'];
                            if (msg === 'end') {
                                clearInterval(msg_request);
                            }
                        }
                    });
                }, 1);
            } else {
                var result_msg = '<p class="checker-result-error"><span>[-] </span>Something error!</p>';
                $('.checker-result')[0].innerHTML = result_msg;
            }
            // var result_msg = '\n';
            // for (var result_index in data) {
            //     var result_dict = data[result_index];
            //     if (result_dict['type'] == 0) {
            //         var msg = result_dict['msg'];
            //         if (msg instanceof Array) {
            //             result_msg += '<p class="checker-result-success"><span>[+] </span>' + '[' + '</p>';
            //             for (var msg_index in msg) {
            //                 result_msg += '<p class="checker-result-success"><span>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span>' + convert_to_str(msg[msg_index]) + ' ,</p>';
            //             }
            //             result_msg += '<p class="checker-result-success"><span>&nbsp;&nbsp;&nbsp;&nbsp;</span>' + ']' + '</p>';
            //         } else if (msg instanceof Object) {
            //             result_msg += '<p class="checker-result-success"><span>[+] </span>' + '{' + '</p>';
            //             for (var msg_index in msg) {
            //                 result_msg += '<p class="checker-result-success"><span>&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;</span>' + msg_index + ' :' + convert_to_str(msg[msg_index]) + ' ,</p>';
            //             }
            //             result_msg += '<p class="checker-result-success"><span>&nbsp;&nbsp;&nbsp;&nbsp;</span>' + '}' + '</p>';
            //         } else {
            //             result_msg += '<p class="checker-result-success"><span>[+] </span>' + result_dict['msg'] + '</p>';
            //         }
            //     } else if (result_dict['type'] == -1) {
            //         result_msg += '<p class="checker-result-error"><span>[-] </span>' + result_dict['msg'] + '</p>';
            //     }
            //     result_msg += '\n';
            // }
            // $('.checker-result')[0].innerHTML = result_msg;
        }
    });
}

function save_button_click() {
    var query = window.location.search.substring(1);
    var p_data = {};
    if (query.length === 0) {
        p_data = {
            'name': $('.editor-file-name')[0].value,
            'old': '',
            'content': $('.code-editor')[0].innerHTML,
            'action': 'new'
        };
    } else {
        p_data = {
            'name': $('.editor-file-name')[0].value,
            'old': checker_file,
            'content': $('.code-editor')[0].innerHTML,
            'action': 'edit'
        };
    }
    $.ajax({
        type: 'POST',
        url: '/analysis/binary/save',
        data: p_data,
        success: function (data) {
            location.href = './edit?ch=' + data;
        }
    })
}

function delete_button_click() {
    $.ajax({
        type: 'POST',
        url: '/analysis/binary/delete',
        data: $('.editor-file-name')[0].value,
        success: function (data) {
            if (data == 'OK') {
                location.href = '../checkers'
            }
        }
    })
}