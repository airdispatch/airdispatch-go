angular.module('DispatchApp.controllers', []).
    controller('DispatchCtrl', function ($scope, $http) {
    $scope.items = [{title: "Could you do this?", owner: {name:"Hunter Leah", gravatar:"e9abd41f117ce7e267885a9a3bc98f0c"}, importance:10, type:"action" },
        {title: "Read this!", owner: {name:"Hunter Leah", gravatar:"e9abd41f117ce7e267885a9a3bc98f0c"}, importance:6, type:"read" },
        {title: "Reply needed!", owner: {name:"Hunter Leah", gravatar:"e9abd41f117ce7e267885a9a3bc98f0c"}, importance:4, type:"reply" }]
});


//sparkBar = new Grafico.SparkBar($('mailHistory'), [30, 15, 50, 20, 50, 12, 45]);
//var sparkBar = new Grafico.SparkLine($('responseTime'), [341,50,123,54,14,69,5]);