$(function () {
    $("#upload-button").on("click", function () {
        $("#file-input").click();
    });

    $("#upload-form").on("submit", function (event) {
        $("#upload-button").attr("disabled", true).text("上传中");
        $(".progress").css("display", "block");

        event.preventDefault();
        let formData = new FormData(this);
        $.ajax({
            xhr: function () {
                let xhr = new XMLHttpRequest();
                xhr.upload.addEventListener("progress", function (e) {
                    if (e.lengthComputable) {
                        let precent = Math.round(e.loaded * 100 / e.total);
                        $(".progress-bar").attr("aria-valuenow", precent).css("width", precent + "%");
                    }
                });
                return xhr;
            },
            type: 'POST',
            url: $("#upload-form").attr('action'),
            cache: false,
            data: formData,
            processData: false,
            contentType: false
        }).done(function (response) {
            if (response != "Error") {
                let file_md5 = response.substr(2, response.length - 2);
                window.location.href = "/analysis/basic/" + file_md5;
            } else {
                $("#upload-button").attr("disabled", false).text("上传");
            }
        }).fail(function (response) {
            $("#upload-button").attr("disabled", false).text("上传");
        });
    });

    $("#file-input").change(function () {
        $("#upload-form").submit();
    })
});