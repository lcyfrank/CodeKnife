$(function () {
    $('.search-input').keydown(function (event) {
        var search_key = $('.search-input')[0].value;
        if (event.keyCode === 13) {
            if (search_key.length > 0) {
                location.href = './classes?search=' + search_key;
            } else {
                location.href = './classes'
            }
        }
    });
});