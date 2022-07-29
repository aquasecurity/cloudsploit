var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var ecs = new AWS.ECS(AWSConfig);

    async.eachOfLimit(collection.ecs.listContainerInstances[AWSConfig.region], 10, function(containerInstanceData,instance, cb){
        async.eachLimit(containerInstanceData.data, 5, function(containerInstance, ccb){
            collection.ecs.describeContainerInstances[AWSConfig.region][containerInstance] = {};

            var parts = containerInstance.split('/');
            const clusterName = parts[parts.length - 2];
            // Check for the multiple subnets in that single VPC
            var params = {
                containerInstances: [containerInstance],
                cluster : clusterName,
            };collection.ecs.describeContainerInstances[AWSConfig.region][containerInstance] = {};

            helpers.makeCustomCollectorCall(ecs, 'describeContainerInstances', params, retries, null, null, null, function(err, data) {
                if (err) {
                    collection.ecs.describeContainerInstances[AWSConfig.region][containerInstance].err = err;
                }

                collection.ecs.describeContainerInstances[AWSConfig.region][containerInstance].data = data;

                ccb();
            });
        }, function(){
            cb();
        });

    }, function(){
        callback();
    });
};