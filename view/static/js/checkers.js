$(function () {
    $('.new-button').click(function () {
        location.href = './checkers/edit'
    });

    $('input[type=checkbox]').change(function () {
        if (this.checked) {
            $('.checkers-gallery').hide();
            $('.checkers-list').show();
        } else {
            $('.checkers-list').hide();
            $('.checkers-gallery').show();
        }
    });
});