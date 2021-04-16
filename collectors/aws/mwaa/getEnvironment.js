var AWS = require('aws-sdk');
var async = require('async');

module.exports = function(AWSConfig, collection, callback) {
    var mwaa = new AWS.MWAA(AWSConfig);

    async.eachLimit(collection.mwaa.listEnvironments[AWSConfig.region].data, 15, function(env, cb){
        collection.mwaa.getEnvironment[AWSConfig.region][env] = {};

        var params = {
            Name: env
        };

        mwaa.getEnvironment(params, function(err, data) {
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