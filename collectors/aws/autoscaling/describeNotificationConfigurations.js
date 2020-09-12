var AWS = require('aws-sdk');
var async = require('async');

module.exports = function(AWSConfig, collection, callback) {
    var autoscaling = new AWS.AutoScaling(AWSConfig);

    async.eachLimit(collection.autoscaling.describeAutoScalingGroups[AWSConfig.region].data, 15, function(asg, cb){        
        var params = {
            'AutoScalingGroupNames':[asg.AutoScalingGroupName]
        };

        autoscaling.describeNotificationConfigurations(params, function(err, data) {
            collection.autoscaling.describeNotificationConfigurations[AWSConfig.region][asg.AutoScalingGroupARN] = {};
            if (err || !data) {
                collection.autoscaling.describeNotificationConfigurations[AWSConfig.region][asg.AutoScalingGroupARN].err = err;
            } else {
                collection.autoscaling.describeNotificationConfigurations[AWSConfig.region][asg.AutoScalingGroupARN].data = data;
            }
            cb();
        });
                
    }, function(){
        callback();
    });
};
