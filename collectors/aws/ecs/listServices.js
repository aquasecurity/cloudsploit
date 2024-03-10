const {
    ECS
} = require('@aws-sdk/client-ecs');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var ecs = new ECS(AWSConfig);

    async.eachLimit(collection.ecs.listClusters[AWSConfig.region].data, 10, function(cluster, cb){
        collection.ecs.listServices[AWSConfig.region][cluster] = {};

        var parts = cluster.split('/');
        const clusterName = parts[parts.length - 1];

        var params = {
            cluster: clusterName
        };

        helpers.makeCustomCollectorCall(ecs, 'listServices', params, retries, null, null, null, function(err, data) {
            if (err) {
                collection.ecs.listServices[AWSConfig.region][cluster].err = err;
            }

            collection.ecs.listServices[AWSConfig.region][cluster].data = data.serviceArns;

            cb();
        });
    }, function(){
        callback();
    });
};