var AWS = require('aws-sdk');
var async = require('async');

module.exports = function(AWSConfig, collection, callback) {
    var cloudfront = new AWS.CloudFront(AWSConfig);

    async.eachLimit(collection.cloudfront.listDistributions[AWSConfig.region].data, 15, function(distribution, cb){        
        collection.cloudfront.getDistribution[AWSConfig.region][distribution.Id] = {};
        var params = {
            'Id':distribution.Id
        };

        cloudfront.getDistribution(params, function(err, data) {
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
