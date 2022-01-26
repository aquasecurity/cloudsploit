var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var apigateway = new AWS.APIGateway(AWSConfig);

    async.eachLimit(collection.apigateway.getRestApis[AWSConfig.region].data, 5, function(api, cb){
        if (!collection.apigateway.getStages ||
            !collection.apigateway.getStages[AWSConfig.region] ||
            !collection.apigateway.getStages[AWSConfig.region][api.id] ||
            !collection.apigateway.getStages[AWSConfig.region][api.id].data ||
            !collection.apigateway.getStages[AWSConfig.region][api.id].data.item) {
            return cb();
        }

        async.eachLimit(collection.apigateway.getStages[AWSConfig.region][api.id].data.item, 3, function(stage, pCb){
            collection.apigateway.getClientCertificate[AWSConfig.region][stage.clientCertificateId] = {};

            let params = {
                clientCertificateId: stage.clientCertificateId
            };

            helpers.makeCustomCollectorCall(apigateway, 'getClientCertificate', params, retries, null, null, null, function(err, data) {
                if (err) {
                    collection.apigateway.getClientCertificate[AWSConfig.region][stage.clientCertificateId].err = err;
                    return pCb();
                }
                collection.apigateway.getClientCertificate[AWSConfig.region][stage.clientCertificateId].data = data;
                pCb();
            });

        }, function(){
            cb();
        });

    }, function(){
        callback();
    });
};