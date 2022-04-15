var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var mwaa = new AWS.MWAA(AWSConfig);

    async.eachLimit(collection.mwaa.listEnvironments[AWSConfig.region].data, 15, function(env, cb){
        collection.mwaa.getEnvironment[AWSConfig.region][env] = {};

        var params = {
            Name: env
        };

        helpers.makeCustomCollectorCall(mwaa, 'getEnvironment', params, retries, null, null, null, function(err, data) {
            if (err) {
                collection.mwaa.getEnvironment[AWSConfig.region][env].err = err;
            }
            collection.mwaa.getEnvironment[AWSConfig.region][env].data = data;
            cb();
        });
    }, function(){
        callback();
    });
};