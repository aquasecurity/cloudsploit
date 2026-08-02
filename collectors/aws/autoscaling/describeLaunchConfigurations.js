const {
    AutoScaling
} = require('@aws-sdk/client-auto-scaling');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var autoscaling = new AutoScaling(AWSConfig);

    async.eachLimit(collection.autoscaling.describeAutoScalingGroups[AWSConfig.region].data, 15, function(asg, cb){
        collection.autoscaling.describeLaunchConfigurations[AWSConfig.region][asg.AutoScalingGroupARN] = {};
        var params = {
            'LaunchConfigurationNames': [asg.LaunchConfigurationName]
        };

        helpers.makeCustomCollectorCall(autoscaling, 'describeLaunchConfigurations', params, retries, null, null, null, function(err, data) {
            if (err) {
                collection.autoscaling.describeLaunchConfigurations[AWSConfig.region][asg.AutoScalingGroupARN].err = err;
            }
            if (data) collection.autoscaling.describeLaunchConfigurations[AWSConfig.region][asg.AutoScalingGroupARN].data = data;

            cb();
        });
    }, function(){
        callback();
    });
}; 