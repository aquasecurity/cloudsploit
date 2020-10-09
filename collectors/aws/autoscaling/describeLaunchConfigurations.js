var AWS = require('aws-sdk');
var async = require('async');

module.exports = function(AWSConfig, collection, callback) {
    var autoscaling = new AWS.AutoScaling(AWSConfig);

    console.log('here');
    async.eachLimit(collection.autoscaling.describeAutoScalingGroups[AWSConfig.region].data, 15, function(asg, cb){
        collection.autoscaling.describeLaunchConfigurations[AWSConfig.region][asg.AutoScalingGroupName] = {};
        var params = {
            'LaunchConfigurationNames': [asg.LaunchConfigurationName]
        };
        autoscaling.describeLaunchConfigurations(params, function(err, data){
            if (err) {
                collection.autoscaling.describeLaunchConfigurations[AWSConfig.region][asg.AutoScalingGroupName].err = err;
            }
                collection.autoscaling.describeLaunchConfigurations[AWSConfig.region][asg.AutoScalingGroupName].data = data;

            cb();
        });
    }, function(){
        callback();
    });
}; 