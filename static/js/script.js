$( document ).ready(function(){
    // Like/unlike a warble, shouldn’t have to refresh the page
    $("button.like-button").on("click", function(evt){
        evt.preventDefault();
        let $like_button = $(this);
        let msg_url = $like_button.attr("data-url");
        $.ajax({
            url: msg_url
        }).done(function(){
            $like_button.toggleClass("btn-primary");
            $like_button.toggleClass("btn-secondary");
        });
    });

    // Compose a warble via a popup modal
    function addNewMsg(){
        $("#newMsgButton").on("click", function(evt){
            evt.preventDefault();
            let posting = $.post("/messages/new", $("#newMsgForm").serialize());
            posting.done(function(res){
                $("#newMsgModal").modal("hide");
                $(location).attr('href', res);
            });
        }); 
    }
    $("#newMsgModal .modal-body").load("/messages/new");
    $("#newMsgModalButton").on("click", function(evt){
        evt.preventDefault();
        $("#newMsgModal").modal("show");
        addNewMsg();
    });
});