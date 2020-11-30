var AWS = require('aws-sdk');
var async = require('async');

module.exports = function(AWSConfig, collection, callback) {
    var ecs = new AWS.ECS(AWSConfig);

    async.eachLimit(collection.ecs.listClusters[AWSConfig.region].data, 10, function(cluster, cb){
        collection.ecs.listContainerInstances[AWSConfig.region][cluster] = {};

        // Check for the multiple subnets in that single VPC
        var params = {
            cluster: cluster
        };

        ecs.listContainerInstances(params, function(err, data) {
            if (err) {
                collection.ecs.listContainerInstances[AWSConfig.region][cluster].err = err;
            }

            collection.ecs.listContainerInstances[AWSConfig.region][cluster].data = data.containerInstanceArns;

            cb();
        });
    }, function(){
        callback();
    });
};