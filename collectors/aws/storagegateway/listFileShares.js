var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, settings, scanAWSConfig, callback) {
    var storagegateway = new AWS.StorageGateway(AWSConfig);

    // Stored as a flat list rather than keyed by gateway so that the
    // describe*FileShares postcalls can depend on it in the usual way
    collection.storagegateway.listFileShares[AWSConfig.region].data = [];

    async.eachLimit(collection.storagegateway.listGateways[AWSConfig.region].data, 5, function(gateway, cb){
        var paginateCb = function(err, data) {
            if (err) {
                collection.storagegateway.listFileShares[AWSConfig.region].err = err;
                return cb();
            }

            if (data && data.FileShareInfoList && data.FileShareInfoList.length) {
                collection.storagegateway.listFileShares[AWSConfig.region].data =
                    collection.storagegateway.listFileShares[AWSConfig.region].data.concat(data.FileShareInfoList);
            }

            // NextMarker is the token; it is sent back as Marker
            if (data && data.NextMarker && data.NextMarker.length) {
                return execute(data.NextMarker);
            }

            cb();
        };

        function execute(marker) {
            var params = {
                GatewayARN: gateway.GatewayARN
            };
            if (marker) params.Marker = marker;

            helpers.makeCustomCollectorCall(storagegateway, 'listFileShares', params, retries, null, null, null, settings, scanAWSConfig, AWSConfig, paginateCb);
        }

        execute();
    }, function(){
        callback();
    });
};
