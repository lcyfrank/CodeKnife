$(function () {
    $("#upload-button").click(function () {
        $("#file-input").click();
    })

    $("#file-input").change(function () {
        $("#upload-form").submit();
    })
})