var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var ecs = new AWS.ECS(AWSConfig);

    async.eachOfLimit(collection.ecs.listServices[AWSConfig.region], 10, function(servicesData,instance, cb){
        async.eachLimit(servicesData.data, 5, function(service, ccb){
            collection.ecs.describeServices[AWSConfig.region][service] = {};

            var parts = service.split('/');
            const clusterName = parts[parts.length - 2];
            // Check for the multiple subnets in that single VPC
            var params = {
                services: [service],
                cluster : clusterName,
            };

            helpers.makeCustomCollectorCall(ecs, 'describeServices', params, retries, null, null, null, function(err, data) {
                if (err) {
                    collection.ecs.describeServices[AWSConfig.region][service].err = err;
                }

                collection.ecs.describeServices[AWSConfig.region][service].data = data;

                ccb();
            });
        }, function(){
            cb();
        });

    }, function(){
        callback();
    });
};