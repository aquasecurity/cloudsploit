var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var apigateway = new AWS.APIGateway(AWSConfig);

    async.eachLimit(collection.apigateway.getRestApis[AWSConfig.region].data, 5, function(api, cb){
        if (!collection.apigateway.getResources ||
            !collection.apigateway.getResources[AWSConfig.region] ||
            !collection.apigateway.getResources[AWSConfig.region][api.id] ||
            !collection.apigateway.getResources[AWSConfig.region][api.id].data ||
            !collection.apigateway.getResources[AWSConfig.region][api.id].data.items) {
            return cb();
        }

        collection.apigateway.getIntegration[AWSConfig.region][api.id] = {};
        async.eachLimit(collection.apigateway.getResources[AWSConfig.region][api.id].data.items, 3, function(resource, pCb){
            
            collection.apigateway.getIntegration[AWSConfig.region][api.id][resource.id] = {};

            async.eachOfLimit(resource.resourceMethods, 3, function(methodVal,methodKey, mCb){

                collection.apigateway.getIntegration[AWSConfig.region][api.id][resource.id][methodKey] = {};

                let params = {
                    resourceId: resource.id,
                    httpMethod: methodKey,
                    restApiId : api.id,
                };

                helpers.makeCustomCollectorCall(apigateway, 'getIntegration', params, retries, null, null, null, function(err, data) {
                    if (err) {
                        collection.apigateway.getIntegration[AWSConfig.region][api.id][resource.id][methodKey].err = err;
                        return mCb();
                    }

                    if (data) collection.apigateway.getIntegration[AWSConfig.region][api.id][resource.id][methodKey].data = data;
                    mCb();
                });
            }, function(){
                pCb();
            });

        }, function(){
            cb();
        });

    }, function(){
        callback();
    });
};