'use strict';
app.controller('tokensManagerController', ['$scope', 'tokensManagerService', function ($scope, tokensManagerService) {

    $scope.refreshTokens = [];

    //토큰 정보 할당하기
    tokensManagerService.getRefreshTokens().then(function (results) {

        $scope.refreshTokens = results.data;

    }, function (error) {
        alert(error.data.message);
    });

    //토큰 삭제하기
    $scope.deleteRefreshTokens = function (index, tokenid) {

        tokenid = window.encodeURIComponent(tokenid);

        tokensManagerService.deleteRefreshTokens(tokenid).then(function (results) {

            $scope.refreshTokens.splice(index, 1);

        }, function (error) {
            alert(error.data.message);
        });
    }

}]);