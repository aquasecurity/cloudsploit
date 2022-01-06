var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var cloudfront = new AWS.CloudFront(AWSConfig);

    async.eachLimit(collection.cloudfront.listDistributions[AWSConfig.region].data, 15, function(distribution, cb){        
        collection.cloudfront.getDistribution[AWSConfig.region][distribution.Id] = {};
        var params = {
            'Id':distribution.Id
        };

        helpers.makeCustomCollectorCall(cloudfront, 'getDistribution', params, retries, null, null, null, function(err, data) {
            if (err) {
                collection.cloudfront.getDistribution[AWSConfig.region][distribution.Id].err = err;
            }
            collection.cloudfront.getDistribution[AWSConfig.region][distribution.Id].data = data;
            cb();
        });
                
    }, function(){
        callback();
    });
};
