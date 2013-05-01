angular.module('DispatchApp.services', []).
    service('mailService', function ($http) {
        var serverUrl = "http://client.airdispat.ch/"
        this.Server = {
            get: getMail,
            send: sendMail,
            login: doLogin
        };

        var getMail = function(callback) {
            $http.get(serverUrl+"message/")
                .success(function(response) {
                    callback(response);
                })
                .error(function(error) {
                    callback(error);
                });
        };

        var sendMail = function( message, title, type, importance, address) {

        };

        var doLogin = function( username, password ) {
            $http.post("login/")
                .success(function(response) {
                    console.log(response);
                    if(response==="ok")
                        return true;
                    return false;
                });
        };
    });