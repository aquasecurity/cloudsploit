var AWS = require('aws-sdk');
var async = require('async');

module.exports = function(AWSConfig, collection, callback) {
    var apigateway = new AWS.APIGateway(AWSConfig);

    async.eachLimit(collection.apigateway.getRestApis[AWSConfig.region].data, 15, function(api, cb){
        if (!collection.apigateway.getStages ||
            !collection.apigateway.getStages[AWSConfig.region] ||
            !collection.apigateway.getStages[AWSConfig.region][api.id] ||
            !collection.apigateway.getStages[AWSConfig.region][api.id].data ||
            !collection.apigateway.getStages[AWSConfig.region][api.id].data.item) {
            return cb();
        }

        async.each(collection.apigateway.getStages[AWSConfig.region][api.id].data.item, function(stage, pCb){
            collection.apigateway.getClientCertificate[AWSConfig.region][stage.clientCertificateId] = {};

            apigateway.getClientCertificate({
                clientCertificateId: stage.clientCertificateId
            }, function(err, data){
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