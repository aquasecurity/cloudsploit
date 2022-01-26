var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var eks = new AWS.EKS(AWSConfig);

    async.eachLimit(collection.eks.listClusters[AWSConfig.region].data, 10, function(cluster, cb){
        collection.eks.listNodegroups[AWSConfig.region][cluster] = {};

        // Check for the multiple subnets in that single VPC
        var params = {
            clusterName: cluster
        };

        helpers.makeCustomCollectorCall(eks, 'listNodegroups', params, retries, null, null, null, function(err, data) {
            if (err) {
                collection.eks.listNodegroups[AWSConfig.region][cluster].err = err;
            }

            collection.eks.listNodegroups[AWSConfig.region][cluster].data = data.nodegroups;

            cb();
        });
    }, function(){
        callback();
    });
};