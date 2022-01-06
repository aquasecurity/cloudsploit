var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var iam = new AWS.IAM(AWSConfig);

    if (!collection.iam ||
        !collection.iam.listPolicies ||
        !collection.iam.listPolicies[AWSConfig.region] ||
        !collection.iam.listPolicies[AWSConfig.region].data) return callback();

    async.eachLimit(collection.iam.listPolicies[AWSConfig.region].data, 10, function(policy, cb){
        if (!policy.Arn ||
            !collection.iam.getPolicy ||
            !collection.iam.getPolicy[AWSConfig.region] ||
            !collection.iam.getPolicy[AWSConfig.region] ||
            !collection.iam.getPolicy[AWSConfig.region][policy.Arn] ||
            !collection.iam.getPolicy[AWSConfig.region][policy.Arn].data ||
            !collection.iam.getPolicy[AWSConfig.region][policy.Arn].data.Policy ||
            !collection.iam.getPolicy[AWSConfig.region][policy.Arn].data.Policy.DefaultVersionId) {
            return cb();
        }

        var versionId = collection.iam.getPolicy[AWSConfig.region][policy.Arn].data.Policy.DefaultVersionId;
        collection.iam.getPolicyVersion[AWSConfig.region][policy.Arn] = {};

        helpers.makeCustomCollectorCall(iam, 'getPolicyVersion', {PolicyArn: policy.Arn, VersionId: versionId}, retries, null, null, null, function(err, data) {
            if (err) {
                collection.iam.getPolicyVersion[AWSConfig.region][policy.Arn].err = err;
            }
            collection.iam.getPolicyVersion[AWSConfig.region][policy.Arn].data = data;
            cb();
        });
    }, function(){
        callback();
    });
};