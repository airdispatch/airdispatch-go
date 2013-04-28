angular.module('DispatchApp.controllers', ['ngResource']).
    service('mailService', function ($resource) {
        var Server = $resource('https://path.to.server/:action',
            {action: 'search.json', q:'Brent', callback: 'JSON_CALLBACK'},
            {get: {method: 'JSONP'}});
        this.getMail = function(user_id) {
            Server.get({q:user_id});
        }
    });