var AWS = require('aws-sdk');
var async = require('async');

module.exports = function(AWSConfig, collection, callback) {
    var ec2 = new AWS.EC2(AWSConfig);

    async.eachLimit(collection.ec2.describeInstances[AWSConfig.region].data, 15, function(instance, cb){

        securityGroups = instance.Instances[0].SecurityGroups

        for (sg of securityGroups) {
            collection.ec2.describeSecurityGroups[AWSConfig.region][sg.GroupId] = {};
            var params = {
                'GroupIds':[sg.GroupId]
            }
            ec2.describeSecurityGroups(params, function(err, data) {
                if (err) {
                    collection.ec2.describeSecurityGroups[AWSConfig.region][sg.GroupId].err = err;
                }
                collection.ec2.describeSecurityGroups[AWSConfig.region][sg.GroupId].data = data;
                cb();
            });
        }

    }, function(){
        callback();
    });
};