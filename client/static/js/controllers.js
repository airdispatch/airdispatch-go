angular.module('DispatchApp.controllers', []).
    controller('DispatchCtrl', function ($scope, mailService) {
    $scope.items = [{title: "Could you do this?", owner: {name:"Hunter Leah", gravatar:"e9abd41f117ce7e267885a9a3bc98f0c"}, importance:6, type:"action" },
        {title: "Read this!", owner: {name:"Hunter Leah", gravatar:"e9abd41f117ce7e267885a9a3bc98f0c"}, importance:3, type:"read" },
        {title: "Reply needed!", owner: {name:"Hunter Leah", gravatar:"e9abd41f117ce7e267885a9a3bc98f0c"}, importance:5, type:"reply" }];
    $scope.getMail = function() {
        mailService.getMail(function(data) {
            if(typeof(data)!=="integer")
                $scope.items = data;
            else {
                $scope.showError(data);
            }
        })
    }

    $scope.showError = function(error) {
        console.log('Error: '+ error);
    }

    $scope.login = function(username, password) {
        bool = mailService.doLogin(username, password);
        if(bool) {
            $scope.currentUsername = name;
        }
    }
});


//sparkBar = new Grafico.SparkBar($('mailHistory'), [30, 15, 50, 20, 50, 12, 45]);
//var sparkBar = new Grafico.SparkLine($('responseTime'), [341,50,123,54,14,69,5]);