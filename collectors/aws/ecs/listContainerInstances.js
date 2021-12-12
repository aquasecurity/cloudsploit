var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var ecs = new AWS.ECS(AWSConfig);

    async.eachLimit(collection.ecs.listClusters[AWSConfig.region].data, 10, function(cluster, cb){
        collection.ecs.listContainerInstances[AWSConfig.region][cluster] = {};

        // Check for the multiple subnets in that single VPC
        var params = {
            cluster: cluster
        };

        helpers.makeCustomCollectorCall(ecs, 'listContainerInstances', params, retries, null, null, null, function(err, data) {
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