angular.module('DispatchApp.controllers', ['ngResource']).
    service('mailService', function ($http) {
        var serverUrl = "http://path.to.server/"
        this.Server = {
            get: getMail,
            send: sendMail,
            login: startSession
        };

        var getMail = function(callback) {
            $http.get("message/")
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