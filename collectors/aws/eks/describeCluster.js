var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var eks = new AWS.EKS(AWSConfig);

    async.eachLimit(collection.eks.listClusters[AWSConfig.region].data, 10, function(cluster, cb){
        collection.eks.describeCluster[AWSConfig.region][cluster] = {};

        // Check for the multiple subnets in that single VPC
        var params = {
            name: cluster
        };

        helpers.makeCustomCollectorCall(eks, 'describeCluster', params, retries, null, null, null, function(err, data) {
            if (err) {
                collection.eks.describeCluster[AWSConfig.region][cluster].err = err;
            }

            collection.eks.describeCluster[AWSConfig.region][cluster].data = data;

            cb();
        });
    }, function(){
        callback();
    });
};