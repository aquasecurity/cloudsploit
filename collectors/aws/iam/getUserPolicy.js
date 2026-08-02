const {
    IAM
} = require('@aws-sdk/client-iam');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var iam = new IAM(AWSConfig);

    if (!collection.iam ||
        !collection.iam.listUsers ||
        !collection.iam.listUsers[AWSConfig.region] ||
        !collection.iam.listUsers[AWSConfig.region].data) return callback();

    async.eachLimit(collection.iam.listUsers[AWSConfig.region].data, 5, function(user, cb){
        // Loop through each policy for that user
        if (!user.UserName || !collection.iam ||
            !collection.iam.listUserPolicies ||
            !collection.iam.listUserPolicies[AWSConfig.region] ||
            !collection.iam.listUserPolicies[AWSConfig.region][user.UserName] ||
            !collection.iam.listUserPolicies[AWSConfig.region][user.UserName].data ||
            !collection.iam.listUserPolicies[AWSConfig.region][user.UserName].data.PolicyNames) {
            return cb();
        }

        if (collection.iam.listAttachedUserPolicies &&
            collection.iam.listAttachedUserPolicies[AWSConfig.region] &&
            collection.iam.listAttachedUserPolicies[AWSConfig.region][user.UserName] &&
            collection.iam.listAttachedUserPolicies[AWSConfig.region][user.UserName].data &&
            collection.iam.listAttachedUserPolicies[AWSConfig.region][user.UserName].data.AttachedPolicies &&
            collection.iam.listAttachedUserPolicies[AWSConfig.region][user.UserName].data.AttachedPolicies.length) {
            user.attachedPolicies = collection.iam.listAttachedUserPolicies[AWSConfig.region][user.UserName].data.AttachedPolicies;
        } else {
            user.attachedPolicies = [];
        }

        if (collection.iam.getUser &&
            collection.iam.getUser[AWSConfig.region] &&
            collection.iam.getUser[AWSConfig.region][user.UserName] &&
            collection.iam.getUser[AWSConfig.region][user.UserName].data &&
            collection.iam.getUser[AWSConfig.region][user.UserName].data.User &&
            Object.keys(collection.iam.getUser[AWSConfig.region][user.UserName].data.User).length) {
            user.tags = collection.iam.getUser[AWSConfig.region][user.UserName].data.User.Tags;
        } else {
            user.tags = [];
        }

        collection.iam.getUserPolicy[AWSConfig.region][user.UserName] = {};
        user.inlinePolicies = [];

        async.each(collection.iam.listUserPolicies[AWSConfig.region][user.UserName].data.PolicyNames, function(policyName, pCb){
            collection.iam.getUserPolicy[AWSConfig.region][user.UserName][policyName] = {};

            helpers.makeCustomCollectorCall(iam, 'getUserPolicy', {PolicyName: policyName,UserName: user.UserName}, retries, null, null, null, function(err, data) {
                if (err) {
                    collection.iam.getUserPolicy[AWSConfig.region][user.UserName][policyName].err = err;
                    return pCb();
                }

                if (data['PolicyDocument']) {
                    data['PolicyDocument'] = helpers.normalizePolicyDocument(data['PolicyDocument']);
                }

                collection.iam.getUserPolicy[AWSConfig.region][user.UserName][policyName].data = data;

                delete data['ResponseMetadata'];
                user.inlinePolicies.push(data);

                pCb();
            });
        }, function(){
            setTimeout(function(){
                cb();
            }, 200);
        });
    }, function(){
        callback();
    });
};
