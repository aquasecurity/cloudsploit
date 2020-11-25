var AWS = require('aws-sdk');
var async = require('async');

module.exports = function(AWSConfig, collection, callback) {
    var ecs = new AWS.ECS(AWSConfig);

    async.eachLimit(collection.ecs.listClusters[AWSConfig.region].data, 10, function(cluster, cb){
        collection.ecs.describeCluster[AWSConfig.region][cluster] = {};

        // Check for the multiple subnets in that single VPC
        var params = {
            clusters: [cluster]
        };

        ecs.describeClusters(params, function(err, data) {
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