var USER_IP='208.185.115.6';
var BASE_URL='index.html';
var RETURN_URL='index.html';
var REDIRECT=false;

window.log=function(){
    log.history = log.history || [];
    log.history.push(arguments);
    if(this.console) {
        console.log(Array.prototype.slice.call(arguments));
    }
};
