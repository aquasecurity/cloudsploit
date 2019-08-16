var AWS = require('aws-sdk');
var async = require('async');

module.exports = function(AWSConfig, collection, callback) {
    var iam = new AWS.IAM(AWSConfig);

    if (!collection.iam ||
        !collection.iam.listRoles ||
        !collection.iam.listRoles[AWSConfig.region] ||
        !collection.iam.listRoles[AWSConfig.region].data) return callback();

    async.eachLimit(collection.iam.listRoles[AWSConfig.region].data, 5, function(role, cb){
        // Loop through each policy for that role
        if (!role.RoleName || !collection.iam ||
            !collection.iam.listRolePolicies ||
            !collection.iam.listRolePolicies[AWSConfig.region] ||
            !collection.iam.listRolePolicies[AWSConfig.region][role.RoleName] ||
            !collection.iam.listRolePolicies[AWSConfig.region][role.RoleName].data ||
            !collection.iam.listRolePolicies[AWSConfig.region][role.RoleName].data.PolicyNames) {
            return cb();
        }

        collection.iam.getRolePolicy[AWSConfig.region][role.RoleName] = {};

        async.eachLimit(collection.iam.listRolePolicies[AWSConfig.region][role.RoleName].data.PolicyNames, 5, function(policyName, pCb){
            collection.iam.getRolePolicy[AWSConfig.region][role.RoleName][policyName] = {};

            // Make the policy call
            iam.getRolePolicy({
                PolicyName: policyName,
                RoleName: role.RoleName
            }, function(err, data){
                if (err) {
                    collection.iam.getRolePolicy[AWSConfig.region][role.RoleName][policyName].err = err;
                }

                collection.iam.getRolePolicy[AWSConfig.region][role.RoleName][policyName].data = data;
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