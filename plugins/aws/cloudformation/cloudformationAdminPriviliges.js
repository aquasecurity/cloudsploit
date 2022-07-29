var async = require('async');
var helpers = require('../../../helpers/aws');

var managedAdminPolicy = 'arn:aws:iam::aws:policy/AdministratorAccess';

module.exports = {
    title: 'CloudFormation Admin Priviliges',
    category: 'CloudFormation',
    domain: 'Application Integration',
    severity: 'MEDIUM',
    description: 'Ensures no AWS CloudFormation stacks available in your AWS account has admin privileges.',
    more_info: 'A service role is an AWS Identity and Access Management (IAM) role that allows AWS CloudFormation to make calls to resources in a stack on your behalf. You can specify an IAM role that allows AWS CloudFormation to create, update, or delete your stack resources',
    link: 'https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/using-iam-servicerole.html',
    recommended_action: 'Modify IAM role attached with AWS CloudFormation stack to provide the minimal amount of access required to perform its tasks',
    apis: ['CloudFormation:listStacks', 'CloudFormation:describeStacks', 'IAM:listRoles', 'IAM:listAttachedRolePolicies', 'IAM:listRolePolicies',
        'IAM:listPolicies', 'IAM:getPolicy', 'IAM:getPolicyVersion', 'IAM:getRolePolicy', 'STS:getCallerIdentity'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var defaultRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', defaultRegion, 'data']);

        async.each(regions.cloudformation, function(region, rcb){
            var listStacks = helpers.addSource(cache, source,
                ['cloudformation', 'listStacks', region]);

            if (!listStacks) return rcb();

            if (listStacks.err || !listStacks.data) {
                helpers.addResult(results, 3,
                    `Unable to list CloudFormation stacks: ${helpers.addError(listStacks)}`, region);
                return rcb();
            }

            if (!listStacks.data.length) {
                helpers.addResult(results, 0, 'No CloudFormation stacks found', region);
                return rcb();
            }

            async.each(listStacks.data, function(stack, cb){
                var resource = `arn:${awsOrGov}:cloudformation:${region}:${accountId}:stack/${stack.StackName}`;

                var describeStacks = helpers.addSource(cache, source,
                    ['cloudformation', 'describeStacks', region, stack.StackName]);

                if (!describeStacks || describeStacks.err || !describeStacks.data || !describeStacks.data.Stacks) {
                    helpers.addResult(results, 3,
                        `Unable to query for CloudFormation stack: ${helpers.addError(describeStacks)}`, region, resource);
                    return cb();
                }
               
                if (!describeStacks.data.Stacks[0].RoleARN) {
                    helpers.addResult(results, 0,
                        'CloudFormation stack does not have a role attached', region, resource);
                    return cb();
                }

                var roleName = describeStacks.data.Stacks[0].RoleARN.split('/')[1] ?
                    describeStacks.data.Stacks[0].RoleARN.split('/')[1] : describeStacks.data.Stacks[0].RoleARN;
                var adminPrivileged;

                var listAttachedRolePolicies = helpers.addSource(cache, source,
                    ['iam', 'listAttachedRolePolicies', defaultRegion, roleName]);
                    
                var listRolePolicies = helpers.addSource(cache, source,
                    ['iam', 'listRolePolicies', defaultRegion, roleName]);
                
                var getRolePolicy = helpers.addSource(cache, source,
                    ['iam', 'getRolePolicy', defaultRegion, roleName]);

                if (!listAttachedRolePolicies ||
                    listAttachedRolePolicies.err ||
                    !listAttachedRolePolicies.data ||
                    !listAttachedRolePolicies.data.AttachedPolicies) {
                    helpers.addResult(results, 3,
                        `Unable to query for IAM attached policy for role "${roleName}": ${helpers.addError(listAttachedRolePolicies)}`,
                        region, resource);
                    return cb();
                }

                if (!listRolePolicies || listRolePolicies.err || !listRolePolicies.data || !listRolePolicies.data.PolicyNames) {
                    helpers.addResult(results, 3,
                        `Unable to query for IAM role policy for role "${roleName}": ${helpers.addError(listRolePolicies)}`, 
                        region, resource);
                    return cb();
                }

                for (var policy of listAttachedRolePolicies.data.AttachedPolicies) {
                    if (!policy.PolicyArn) continue;

                    if (policy.PolicyArn === managedAdminPolicy) {
                        helpers.addResult(results, 2,
                            'CloudFormation stack has admin privileges', region, resource);
                        return cb();
                    }

                    var getPolicy = helpers.addSource(cache, source,
                        ['iam', 'getPolicy', defaultRegion, policy.PolicyArn]);

                    if (getPolicy &&
                        getPolicy.data &&
                        getPolicy.data.Policy &&
                        getPolicy.data.Policy.DefaultVersionId) {
                        var getPolicyVersion = helpers.addSource(cache, source,
                            ['iam', 'getPolicyVersion', defaultRegion, policy.PolicyArn]);

                        if (getPolicyVersion &&
                            getPolicyVersion.data &&
                            getPolicyVersion.data.PolicyVersion &&
                            getPolicyVersion.data.PolicyVersion.Document) {
                            let statements = helpers.normalizePolicyDocument(
                                getPolicyVersion.data.PolicyVersion.Document);
                            if (!statements) break;
    
                            // Loop through statements to see if admin privileges
                            for (let statement of statements) {
                                if (statement.Effect && statement.Effect.toUpperCase() === 'ALLOW' &&
                                statement.Action && statement.Action.indexOf('*') > -1 &&
                                statement.Resource && statement.Resource.indexOf('*') > -1) {
                                    adminPrivileged = true;
                                    break;
                                }
                            }
                        }
                    }

                    if (adminPrivileged) break;
                }

                for (var policyName of listRolePolicies.data.PolicyNames) {
                    if (getRolePolicy &&
                        getRolePolicy[policyName] && 
                        getRolePolicy[policyName].data &&
                        getRolePolicy[policyName].data.PolicyDocument) {
                        let statements = helpers.normalizePolicyDocument(
                            getRolePolicy[policyName].data.PolicyDocument);
                        if (!statements) break;

                        // Loop through statements to see if admin privileges
                        for (let statement of statements) {
                            if (statement.Effect && statement.Effect.toUpperCase() === 'ALLOW' &&
                            statement.Action && statement.Action.indexOf('*') > -1 &&
                            statement.Resource && statement.Resource.indexOf('*') > -1) {
                                adminPrivileged = true;
                                break;
                            }
                        }
                    }
                }

                if (!adminPrivileged) {
                    helpers.addResult(results, 0,
                        'CloudFormation stack does not have admin privileges', region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'CloudFormation stack has admin privileges', region, resource);
                }
                
                cb();
            }, function(){
                rcb();
            });
        }, function(){
            callback(null, results, source);
        });
    }
};
