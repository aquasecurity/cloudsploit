// TODO: MOVE TO EC2
var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'App-Tier EC2 Instance IAM Role',
    category: 'EC2',
    description: 'Ensure IAM roles attached with App-Tier EC2 instances have IAM policies attached.',
    more_info: 'EC2 instances should have IAM roles configured with necessary permission to access other AWS services',
    link: 'https://aws.amazon.com/blogs/security/new-attach-an-aws-iam-role-to-an-existing-amazon-ec2-instance-by-using-the-aws-cli/',
    recommended_action: 'Modify EC2 instances to attach IAM roles with required IAM policies',
    apis: ['EC2:describeInstances', 'EC2:describeTags', 'IAM:listRoles', 'IAM:listRolePolicies', 'IAM:listAttachedRolePolicies'],
    settings: {
        ec2_app_tier_tag_key: {
            name: 'EC2 App-Tier Tag Key',
            description: 'Tag key to indicate App-Tier EC2 instances',
            regex: '^.*$s',
            default: ''
        },
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var awsOrGov = helpers.defaultPartition(settings);
        var config = {
            ec2_app_tier_tag_key: settings.ec2_app_tier_tag_key || this.settings.ec2_app_tier_tag_key.default
        };

        if (!config.ec2_app_tier_tag_key.length) return callback(null, results, source);

        async.each(regions.ec2, function(region, rcb){
            var describeInstances = helpers.addSource(
                cache, source, ['ec2', 'describeInstances', region]);

            if (!describeInstances) return rcb();

            if (describeInstances.err || !describeInstances.data) {
                helpers.addResult(results, 3, `Unable to query for instances: ${helpers.addError(describeInstances)}`, region);
                return rcb();
            }

            if (!describeInstances.data.length) {
                helpers.addResult(results, 0, 'No EC2 instances found', region);
                return rcb();
            }

            var describeTags = helpers.addSource(
                cache, source, ['ec2', 'describeTags', region]);

            if (!describeTags || describeTags.err || !describeTags.data) {
                helpers.addResult(results, 3, `Unable to query for tags: ${helpers.addError(describeTags)}`, region);
                return rcb();
            }

            if (!describeTags.data.length) {
                helpers.addResult(results, 0, 'No tags found', region);
                return rcb();
            }

            async.each(describeInstances.data, function(instance, cb){
                var accountId = instance.OwnerId;

                for (var i in instance.Instances) {
                    var entry = instance.Instances[i];
                    var resource = `arn:${awsOrGov}:ec2:${region}:${accountId}:instance/${entry.InstanceId}`;

                    var tagFound = false;
                    for (let t in describeTags.data) {
                        let tag = describeTags.data[t];

                        if(tag.ResourceId && tag.ResourceId === entry.InstanceId &&
                            tag.Key && tag.Key === config.ec2_app_tier_tag_key) {
                            tagFound = true;
                            break;
                        }
                    }

                    if (!tagFound) {
                        helpers.addResult(results, 0, 'Instance does not have App-Tier tag key', region, resource);
                        return cb();
                    }

                    if (!entry.IamInstanceProfile ||
                        !entry.IamInstanceProfile.Arn) {
                        helpers.addResult(results, 2,
                            'Instance does not use an IAM role', region, resource);
                    } else {
                        var roleNameArr = entry.IamInstanceProfile.Arn.split('/');
                        var roleName = roleNameArr[roleNameArr.length-1];
                        
                        // Get managed policies attached to role
                        var listAttachedRolePolicies = helpers.addSource(cache, source,
                            ['iam', 'listAttachedRolePolicies', region, roleName]);


                        if (!listAttachedRolePolicies ||
                            listAttachedRolePolicies.err ||
                            !listAttachedRolePolicies.data ||
                            !listAttachedRolePolicies.data.AttachedPolicies) {
                            helpers.addResult(results, 3,
                                `Unable to query for IAM role policy for role "${roleName}" ${helpers.addError(listAttachedRolePolicies)}`, region, resource);
                            return cb();
                        }

                        if (listAttachedRolePolicies.data.AttachedPolicies.length) {
                            helpers.addResult(results, 0,
                                'IAM role attached with EC2 instance contains policies', region, resource);
                            return cb();
                        }

                        // Get inline policies attached to role
                        var listRolePolicies = helpers.addSource(cache, source,
                            ['iam', 'listRolePolicies', region, roleName]);

                        if (!listRolePolicies ||
                            listRolePolicies.err ||
                            !listRolePolicies.data ||
                            !listRolePolicies.data.PolicyNames) {
                            helpers.addResult(results, 3,
                                `Unable to query for IAM role policy for role "${roleName}" ${helpers.addError(listRolePolicies)}`, region, resource);
                            return cb();
                        }

                        if (listRolePolicies.data.PolicyNames.length) {
                            helpers.addResult(results, 0,
                                'IAM role attached with EC2 instance contains policies', region, resource);
                        } else {
                            helpers.addResult(results, 2,
                                'IAM role attached with EC2 instance does not contain any policies', region, resource);
                        }
                    }
                }
                
                cb();
            });
            
            return rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
