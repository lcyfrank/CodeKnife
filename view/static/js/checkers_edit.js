$(function () {

    var codeArea = $('.code-editor')[0];

    var editor = CodeMirror.fromTextArea(codeArea, {
        lineNumbers: true,
        mode: 'python',
        theme: 'material'
    });
    editor.on('change', () => {
        codeArea.innerHTML = editor.getValue();
    });
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