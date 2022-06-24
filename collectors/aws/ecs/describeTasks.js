var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var ecs = new AWS.ECS(AWSConfig);

    async.eachOfLimit(collection.ecs.listTasks[AWSConfig.region], 10, function(tasksData,instance, cb){
        async.eachLimit(tasksData.data, 5, function(task, ccb){
            collection.ecs.describeTasks[AWSConfig.region][task] = {};

            var parts = task.split('/');
            const clusterName = parts[parts.length - 2];
            // Check for the multiple subnets in that single VPC
            var params = {
                tasks: [task],
                cluster : clusterName,
            };

            helpers.makeCustomCollectorCall(ecs, 'describeTasks', params, retries, null, null, null, function(err, data) {
                if (err) {
                    collection.ecs.describeTasks[AWSConfig.region][task].err = err;
                }

                collection.ecs.describeTasks[AWSConfig.region][task].data = data;

                ccb();
            });
        }, function(){
            cb();
        });

    }, function(){
        callback();
    });
};