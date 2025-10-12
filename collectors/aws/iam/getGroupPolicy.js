const {
    IAM
} = require('@aws-sdk/client-iam');
var async = require('async');
var helpers = require(__dirname + '/../../../helpers/aws');

module.exports = function(AWSConfig, collection, retries, callback) {
    var iam = new IAM(AWSConfig);

    if (!collection.iam ||
        !collection.iam.listGroups ||
        !collection.iam.listGroups[AWSConfig.region] ||
        !collection.iam.listGroups[AWSConfig.region].data) return callback();

    async.eachLimit(collection.iam.listGroups[AWSConfig.region].data, 5, function(group, cb){
        // Loop through each policy for that group
        if (!group.GroupName || !collection.iam ||
            !collection.iam.listGroupPolicies ||
            !collection.iam.listGroupPolicies[AWSConfig.region] ||
            !collection.iam.listGroupPolicies[AWSConfig.region][group.GroupName] ||
            !collection.iam.listGroupPolicies[AWSConfig.region][group.GroupName].data ||
            !collection.iam.listGroupPolicies[AWSConfig.region][group.GroupName].data.PolicyNames) {
            return cb();
        }

        if (group.GroupName && collection.iam &&
            collection.iam.listAttachedGroupPolicies &&
            collection.iam.listAttachedGroupPolicies[AWSConfig.region] &&
            collection.iam.listAttachedGroupPolicies[AWSConfig.region][group.GroupName] &&
            collection.iam.listAttachedGroupPolicies[AWSConfig.region][group.GroupName].data &&
            collection.iam.listAttachedGroupPolicies[AWSConfig.region][group.GroupName].data.AttachedPolicies &&
            collection.iam.listAttachedGroupPolicies[AWSConfig.region][group.GroupName].data.AttachedPolicies.length) {
            group.attachedPolicies = collection.iam.listAttachedGroupPolicies[AWSConfig.region][group.GroupName].data.AttachedPolicies;
        } else {
            group.attachedPolicies = [];
        }

        collection.iam.getGroupPolicy[AWSConfig.region][group.GroupName] = {};
        group.inlinePolicies = [];

        async.eachLimit(collection.iam.listGroupPolicies[AWSConfig.region][group.GroupName].data.PolicyNames, 5, function(policyName, pCb){
            collection.iam.getGroupPolicy[AWSConfig.region][group.GroupName][policyName] = {};

            helpers.makeCustomCollectorCall(iam, 'getGroupPolicy', {PolicyName: policyName, GroupName: group.GroupName}, retries, null, null, null, function(err, data) {
                if (err) {
                    collection.iam.getGroupPolicy[AWSConfig.region][group.GroupName][policyName].err = err;
                    return pCb();
                }

                if (data['PolicyDocument']) {
                    data['PolicyDocument'] = helpers.normalizePolicyDocument(data['PolicyDocument']);
                }

                collection.iam.getGroupPolicy[AWSConfig.region][group.GroupName][policyName].data = data;

                delete data['ResponseMetadata'];
                group.inlinePolicies.push(data);

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