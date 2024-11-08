var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var ecs = new AWS.ECS(AWSConfig);

    async.eachLimit(collection.ecs.listClusters[AWSConfig.region].data, 10, function(cluster, cb){
        collection.ecs.listTasks[AWSConfig.region][cluster] = {};

        var parts = cluster.split('/');
        const clusterName = parts[parts.length - 1];

        var params = {
            cluster: clusterName
        };

        helpers.makeCustomCollectorCall(ecs, 'listTasks', params, retries, null, null, null, function(err, data) {
            if (err) {
                collection.ecs.listTasks[AWSConfig.region][cluster].err = err;
            } else if (data && data.taskArns) {
                collection.ecs.listTasks[AWSConfig.region][cluster].data = data.taskArns;
            }
            cb();
        });
    }, function(){
        callback();
    });
};