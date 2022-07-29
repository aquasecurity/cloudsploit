var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var iam = new AWS.IAM(AWSConfig);

    if (!collection.ec2 ||
        !collection.ec2.describeInstances ||
        !Object.keys(collection.ec2.describeInstances).length) return callback();
    async.eachOfLimit(collection.ec2.describeInstances, 5, function(regionInstances, region, rcb){
        if (!collection.ec2 ||
            !regionInstances.data ||
            !regionInstances.data.length) return rcb();

        async.eachLimit(regionInstances.data, 5, function(parent, cb){
            if (!parent.Instances || !parent.Instances.length) return cb();
            // Loop through each policy for that role
            let instance = parent.Instances[0];

            if (!instance.IamInstanceProfile || !instance.IamInstanceProfile.Arn) {
                return cb();
            }

            let iamInstanceProfileName = instance.IamInstanceProfile.Arn.split('/')[1];

            if (collection.iam.getInstanceProfile[AWSConfig.region][instance.IamInstanceProfile.Arn]) return cb();

            collection.iam.getInstanceProfile[AWSConfig.region][instance.IamInstanceProfile.Arn] = {};

            helpers.makeCustomCollectorCall(iam, 'getInstanceProfile', {InstanceProfileName: iamInstanceProfileName}, retries, null, null, null, function(err, data) {
                if (err) {
                    collection.iam.getInstanceProfile[AWSConfig.region][instance.IamInstanceProfile.Arn].err = err;
                }
                if (data && data.InstanceProfile) {
                    collection.iam.getInstanceProfile[AWSConfig.region][instance.IamInstanceProfile.Arn].data = data.InstanceProfile;
                } else {
                    collection.iam.getInstanceProfile[AWSConfig.region][instance.IamInstanceProfile.Arn].data = data;
                }

                cb();
            });

        }, function(){
            rcb();
        });
    }, function() {
        callback();
    });
};