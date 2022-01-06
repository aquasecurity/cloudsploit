var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var ecs = new AWS.ECS(AWSConfig);

    async.eachLimit(collection.ecs.listClusters[AWSConfig.region].data, 10, function(cluster, cb){
        collection.ecs.describeCluster[AWSConfig.region][cluster] = {};

        // Check for the multiple subnets in that single VPC
        var params = {
            clusters: [cluster]
        };

        helpers.makeCustomCollectorCall(ecs, 'describeClusters', params, retries, null, null, null, function(err, data) {
            if (err) {
                collection.ecs.describeCluster[AWSConfig.region][cluster].err = err;
            }

            collection.ecs.describeCluster[AWSConfig.region][cluster].data = data;

            cb();
        });
    }, function(){
        callback();
    });
};