var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Lambda Admin Privileges',
    category: 'Lambda',
    domain: 'Serverless',
    severity: 'Medium',
    description: 'Ensures no Lambda function available in your AWS account has admin privileges.',
    more_info: 'AWS Lambda Function should have most-restrictive IAM permissions for Lambda security best practices.',
    link: 'https://docs.aws.amazon.com/lambda/latest/dg/lambda-permissions.html',
    recommended_action: 'Modify IAM role attached with Lambda function to provide the minimal amount of access required to perform its tasks',
    apis: ['Lambda:listFunctions', 'IAM:listRoles', 'IAM:listAttachedRolePolicies', 'IAM:listRolePolicies',
        'IAM:listPolicies', 'IAM:getPolicy', 'IAM:getPolicyVersion', 'IAM:getRolePolicy'],
    realtime_triggers: ['lambda:CreateFunction','lambda:UpdateFunctionConfiguration', 'lambda:DeleteFunction'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var defaultRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);

        var managedAdminPolicy = `arn:${awsOrGov}:iam::aws:policy/AdministratorAccess`;

        async.each(regions.lambda, function(region, rcb){
            var listFunctions = helpers.addSource(cache, source,
                ['lambda', 'listFunctions', region]);

            if (!listFunctions) return rcb();
            if (listFunctions.err || !listFunctions.data) {
                helpers.addResult(results, 3,
                    `Unable to query for Lambda functions: ${helpers.addError(listFunctions)}`, region);
                return rcb();
            }

            if (!listFunctions.data.length) {
                helpers.addResult(results, 0, 'No Lambda functions found', region);
                return rcb();
            }

            async.each(listFunctions.data, function(lambdaFunc, fcb){
                if (!lambdaFunc.FunctionArn) return fcb();

                var resource = lambdaFunc.FunctionArn;
                var adminPrivileged;

                if (!lambdaFunc.Role) {
                    helpers.addResult(results, 2,
                        'Function does not have a role attached', region, resource);
                    return fcb();
                }

                var roleNameArr = lambdaFunc.Role.split('/');
                var roleName = roleNameArr[roleNameArr.length - 1];

                var listAttachedRolePolicies = helpers.addSource(cache, source,
                    ['iam', 'listAttachedRolePolicies', defaultRegion, roleName]);
                var listRolePolicies = helpers.addSource(cache, source,
                    ['iam', 'listRolePolicies', defaultRegion, roleName]);
                var getRolePolicy = helpers.addSource(cache, source,
                    ['iam', 'getRolePolicy', defaultRegion, roleName]);

                if (!listAttachedRolePolicies || !listRolePolicies) {
                    helpers.addResult(results, 0,
                        'No IAM Attached Role Found',
                        region, resource);
                    return fcb();
                }

                if (listAttachedRolePolicies.err || !listAttachedRolePolicies.data) {
                    helpers.addResult(results, 3,
                        `Unable to query for IAM attached policy for role "${roleName}": ${helpers.addError(listAttachedRolePolicies)}`,
                        region, resource);
                    return fcb();
                }

                if (listRolePolicies.err || !listRolePolicies.data) {
                    helpers.addResult(results, 3,
                        `Unable to query for IAM role policy for role "${roleName}": ${helpers.addError(listRolePolicies)}`,
                        region, resource);
                    return fcb();
                }

                var listRoles = helpers.addSource(cache, source, ['iam', 'listRoles', defaultRegion]);
                var enrichedRole = null;
                if (listRoles && listRoles.data && Array.isArray(listRoles.data)) {
                    enrichedRole = listRoles.data.find(r => r.RoleName === roleName);
                }

                var hasAttachedPolicies = listAttachedRolePolicies.data.AttachedPolicies && listAttachedRolePolicies.data.AttachedPolicies.length;
                var hasInlinePolicies = listRolePolicies.data.PolicyNames && listRolePolicies.data.PolicyNames.length;

                var attachedPolicies = hasAttachedPolicies
                    ? listAttachedRolePolicies.data.AttachedPolicies
                    : (enrichedRole && enrichedRole.attachedPolicies && Array.isArray(enrichedRole.attachedPolicies) && enrichedRole.attachedPolicies.length
                        ? enrichedRole.attachedPolicies : []);

                var inlinePolicyNames = hasInlinePolicies
                    ? listRolePolicies.data.PolicyNames
                    : (enrichedRole && enrichedRole.inlinePolicies && Array.isArray(enrichedRole.inlinePolicies) && enrichedRole.inlinePolicies.length
                        ? enrichedRole.inlinePolicies : []);

                // check attached managed policies
                for (var policy of attachedPolicies) {
                    if (!policy.PolicyArn) continue;
                    if (policy.PolicyArn === managedAdminPolicy) {
                        adminPrivileged = true;
                        break;
                    }

                    var getPolicy = helpers.addSource(cache, source,
                        ['iam', 'getPolicy', defaultRegion, policy.PolicyArn]);
                    if (getPolicy && getPolicy.data && getPolicy.data.Policy && getPolicy.data.Policy.DefaultVersionId) {
                        var getPolicyVersion = helpers.addSource(cache, source,
                            ['iam', 'getPolicyVersion', defaultRegion, policy.PolicyArn]);
                        if (getPolicyVersion && getPolicyVersion.data && getPolicyVersion.data.PolicyVersion && getPolicyVersion.data.PolicyVersion.Document) {
                            let statements = helpers.normalizePolicyDocument(getPolicyVersion.data.PolicyVersion.Document);
                            if (!statements) continue;

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
                for (var policyName of inlinePolicyNames) {
                    if (getRolePolicy && getRolePolicy[policyName] && getRolePolicy[policyName].data && getRolePolicy[policyName].data.PolicyDocument) {
                        let statements = helpers.normalizePolicyDocument(getRolePolicy[policyName].data.PolicyDocument);
                        if (!statements) continue;
                        for (let statement of statements) {
                            if (statement.Effect && statement.Effect.toUpperCase() === 'ALLOW' &&
                                statement.Action && statement.Action.indexOf('*') > -1 &&
                                statement.Resource && statement.Resource.indexOf('*') > -1) {
                                adminPrivileged = true;
                                break;
                            }
                        }
                    }
                    if (adminPrivileged) break;
                }

                // final decision
                if (!adminPrivileged) {
                    helpers.addResult(results, 0,
                        'Function does not have admin privileges', region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'Function has admin privileges', region, resource);
                }

                fcb();
            });
            
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};