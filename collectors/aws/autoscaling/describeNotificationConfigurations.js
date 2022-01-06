var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var autoscaling = new AWS.AutoScaling(AWSConfig);

    async.eachLimit(collection.autoscaling.describeAutoScalingGroups[AWSConfig.region].data, 15, function(asg, cb){        
        var params = {
            'AutoScalingGroupNames':[asg.AutoScalingGroupName]
        };

        helpers.makeCustomCollectorCall(autoscaling, 'describeNotificationConfigurations', params, retries, null, null, null, function(err, data) {
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
