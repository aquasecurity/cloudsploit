var AWS = require('aws-sdk');
var async = require('async');

module.exports = function(AWSConfig, collection, callback) {
    var iam = new AWS.IAM(AWSConfig);

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

        collection.iam.getUserPolicy[AWSConfig.region][user.UserName] = {};

        async.each(collection.iam.listUserPolicies[AWSConfig.region][user.UserName].data.PolicyNames, function(policyName, pCb){
            collection.iam.getUserPolicy[AWSConfig.region][user.UserName][policyName] = {};

            // Make the policy call
            iam.getUserPolicy({
                PolicyName: policyName,
                UserName: user.UserName
            }, function(err, data){
                if (err) {
                    collection.iam.getUserPolicy[AWSConfig.region][user.UserName][policyName].err = err;
                }

                collection.iam.getUserPolicy[AWSConfig.region][user.UserName][policyName].data = data;
                pCb();
            });
        }, function(){
            setTimeout(function(){
                cb();
            }, 100);
        });
    }, function(){
        callback();
    });
};