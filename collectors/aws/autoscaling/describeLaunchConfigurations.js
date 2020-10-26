var AWS = require('aws-sdk');
var async = require('async');

module.exports = function(AWSConfig, collection, callback) {
    var autoscaling = new AWS.AutoScaling(AWSConfig);

    async.eachLimit(collection.autoscaling.describeAutoScalingGroups[AWSConfig.region].data, 15, function(asg, cb){
        collection.autoscaling.describeLaunchConfigurations[AWSConfig.region][asg.AutoScalingGroupARN] = {};
        var params = {
            'LaunchConfigurationNames': [asg.LaunchConfigurationName]
        };
        autoscaling.describeLaunchConfigurations(params, function(err, data){
            if (err) {
                collection.autoscaling.describeLaunchConfigurations[AWSConfig.region][asg.AutoScalingGroupARN].err = err;
            }
            collection.autoscaling.describeLaunchConfigurations[AWSConfig.region][asg.AutoScalingGroupARN].data = data;

            cb();
        });
    }, function(){
        callback();
    });
}; 