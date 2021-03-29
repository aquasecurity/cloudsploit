var async = require('async');
var helpers = require('../../../helpers/aws');

var managedAdminPolicy = 'arn:aws:iam::aws:policy/AdministratorAccess';

module.exports = {
    title: 'Environment Admin Privileges',
    category: 'MWAA',
    description: 'Ensures no Amazon MWAA environment available in your AWS account has admin privileges.',
    more_info: 'Amazon MWAA environments should have most-restrictive IAM permissions for security best practices.',
    link: 'https://docs.aws.amazon.com/mwaa/latest/userguide/manage-access.html',
    recommended_action: 'Modify IAM role attached with MWAA environment to provide the minimal amount of access required to perform its tasks',
    apis: ['MWAA:listEnvironments', 'MWAA:getEnvironment', 'IAM:listRoles', 'IAM:listAttachedRolePolicies', 'IAM:listRolePolicies',
        'IAM:listPolicies', 'IAM:getPolicy', 'IAM:getPolicyVersion', 'IAM:getRolePolicy', 'STS:getCallerIdentity'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var defaultRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', defaultRegion, 'data']);

        async.each(regions.mwaa, function(region, rcb){
            var listEnvironments = helpers.addSource(cache, source,
                ['mwaa', 'listEnvironments', region]);

            if (!listEnvironments) return rcb();

            if (listEnvironments.err || !listEnvironments.data) {
                helpers.addResult(results, 3,
                    `Unable to query for Airflow environments: ${helpers.addError(listEnvironments)}`, region);
                return rcb();
            }

            if (!listEnvironments.data.length) {
                helpers.addResult(results, 0, 'No Airflow environments found', region);
                return rcb();
            }

            async.each(listEnvironments.data, function(airflowEnv, cb){
                var resource = `arn:${awsOrGov}:airflow:${region}:${accountId}:environment/${airflowEnv}`;

                var getEnvironment = helpers.addSource(cache, source,
                    ['mwaa', 'getEnvironment', region, airflowEnv]);

                if (!getEnvironment || getEnvironment.err || !getEnvironment.data || !getEnvironment.data.Environment) {
                    helpers.addResult(results, 3,
                        `Unable to get Airflow environment: ${helpers.addError(getEnvironment)}`, region, resource);
                    return cb();
                }

                if (!getEnvironment.data.Environment.ExecutionRoleArn) {
                    helpers.addResult(results, 0,
                        'Airflow environment does not have a role attached', region, resource);
                    return cb();
                }
                
                var roleNameArr = getEnvironment.data.Environment.ExecutionRoleArn.split('/');
                var roleName = roleNameArr[roleNameArr.length - 1];
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
                            'Airflow environment has admin privileges', region, resource);
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
                        'Airflow environment does not have admin privileges', region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'Airflow environment has admin privileges', region, resource);
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
