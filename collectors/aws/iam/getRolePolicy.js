var AWS = require('aws-sdk');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
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

        if (collection.iam.listAttachedRolePolicies &&
            collection.iam.listAttachedRolePolicies[AWSConfig.region] &&
            collection.iam.listAttachedRolePolicies[AWSConfig.region][role.RoleName] &&
            collection.iam.listAttachedRolePolicies[AWSConfig.region][role.RoleName].data &&
            collection.iam.listAttachedRolePolicies[AWSConfig.region][role.RoleName].data.AttachedPolicies &&
            collection.iam.listAttachedRolePolicies[AWSConfig.region][role.RoleName].data.AttachedPolicies.length) {
            role.attachedPolicies = collection.iam.listAttachedRolePolicies[AWSConfig.region][role.RoleName].data.AttachedPolicies;
        } else {
            role.attachedPolicies = [];
        }

        if (collection.iam.getRole &&
            collection.iam.getRole[AWSConfig.region] &&
            collection.iam.getRole[AWSConfig.region][role.RoleName] &&
            collection.iam.getRole[AWSConfig.region][role.RoleName].data &&
            collection.iam.getRole[AWSConfig.region][role.RoleName].data.Role &&
            Object.keys(collection.iam.getRole[AWSConfig.region][role.RoleName].data.Role).length) {
            role.tags = collection.iam.getRole[AWSConfig.region][role.RoleName].data.Role.Tags;
            role.lastUsed = collection.iam.getRole[AWSConfig.region][role.RoleName].data.Role.RoleLastUsed;
        } else {
            role.tags = [];
            role.lastUsed = [];
        }

        collection.iam.getRolePolicy[AWSConfig.region][role.RoleName] = {};
        role.inlinePolicies = [];

        async.eachLimit(collection.iam.listRolePolicies[AWSConfig.region][role.RoleName].data.PolicyNames, 5, function(policyName, pCb){
            collection.iam.getRolePolicy[AWSConfig.region][role.RoleName][policyName] = {};

            helpers.makeCustomCollectorCall(iam, 'getRolePolicy', {PolicyName: policyName,RoleName: role.RoleName}, retries, null, null, null, function(err, data) {
                if (err) {
                    collection.iam.getRolePolicy[AWSConfig.region][role.RoleName][policyName].err = err;
                    return pCb();
                }

                if (data['PolicyDocument']) {
                    data['PolicyDocument'] = helpers.normalizePolicyDocument(data['PolicyDocument']);
                }

                collection.iam.getRolePolicy[AWSConfig.region][role.RoleName][policyName].data = data;

                delete data['ResponseMetadata'];

                role.inlinePolicies.push(data);

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