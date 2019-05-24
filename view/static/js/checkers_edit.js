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

        if ($('.editor-save-button')[0].disabled === true && name_input.length > 0)
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

function execute_code() {
    var codeArea = $('.code-editor')[0];

    $.ajax({
        type: 'POST',
        url: '/analysis/binary/' + file_md5 + '/execute',
        data: codeArea.innerHTML,
        success: function (data) {
            $('.checker-result')[0].innerHTML = data;
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