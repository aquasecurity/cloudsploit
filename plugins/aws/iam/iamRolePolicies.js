var async = require('async');
var helpers = require('../../../helpers/aws');

var managedAdminPolicy = 'arn:aws:iam::aws:policy/AdministratorAccess';

module.exports = {
    title: 'IAM Role Policies',
    category: 'IAM',
    description: 'Ensures IAM role policies are properly scoped with specific permissions',
    more_info: 'Policies attached to IAM roles should be scoped to least-privileged access and avoid the use of wildcards.',
    link: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html',
    recommended_action: 'Ensure that all IAM roles are scoped to specific services and API calls.',
    apis: ['IAM:listRoles', 'IAM:listRolePolicies', 'IAM:listAttachedRolePolicies',
           'IAM:getPolicy', 'IAM:getRolePolicy'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        
        var region = helpers.defaultRegion(settings);

        var listRoles = helpers.addSource(cache, source,
                ['iam', 'listRoles', region]);

        if (!listRoles) return callback(null, results, source);

        if (listRoles.err || !listRoles.data) {
            helpers.addResult(results, 3,
                'Unable to query for IAM roles: ' + helpers.addError(listRoles));
            return callback(null, results, source);
        }

        if (!listRoles.data.length) {
            helpers.addResult(results, 0, 'No IAM roles found');
            return callback(null, results, source);
        }

        async.each(listRoles.data, function(role, cb){
            if (!role.RoleName) return cb();

            // Get managed policies attached to role
            var listAttachedRolePolicies = helpers.addSource(cache, source,
                    ['iam', 'listAttachedRolePolicies', region, role.RoleName]);

            // Get inline policies attached to role
            var listRolePolicies = helpers.addSource(cache, source,
                    ['iam', 'listRolePolicies', region, role.RoleName]);

            var getRolePolicy = helpers.addSource(cache, source,
                    ['iam', 'getRolePolicy', region, role.RoleName]);

            if (listAttachedRolePolicies.err) {
                helpers.addResult(results, 3,
                    'Unable to query for IAM attached policy for role: ' + role.RoleName + ': ' + helpers.addError(listAttachedRolePolicies), 'global', role.Arn);
                return cb();
            }

            if (listRolePolicies.err) {
                helpers.addResult(results, 3,
                    'Unable to query for IAM role policy for role: ' + role.RoleName + ': ' + helpers.addError(listRolePolicies), 'global', role.Arn);
                return cb();
            }

            var roleFailures = [];
            var roleWarnings = [];

            // See if role has admin managed policy
            if (listAttachedRolePolicies &&
                listAttachedRolePolicies.data &&
                listAttachedRolePolicies.data.AttachedPolicies) {

                for (a in listAttachedRolePolicies.data.AttachedPolicies) {
                    var policy = listAttachedRolePolicies.data.AttachedPolicies[a];

                    if (policy.PolicyArn === managedAdminPolicy) {
                        roleFailures.push('Role has managed AdministratorAccess policy');
                        break;
                    }
                }
            }

            // See if role has admin inline policy
            if (listRolePolicies &&
                listRolePolicies.data &&
                listRolePolicies.data.PolicyNames) {

                for (p in listRolePolicies.data.PolicyNames) {
                    var policy = listRolePolicies.data.PolicyNames[p];

                    if (getRolePolicy &&
                        getRolePolicy[policy] && 
                        getRolePolicy[policy].data &&
                        getRolePolicy[policy].data.PolicyDocument) {

                        var statements = helpers.normalizePolicyDocument(
                            getRolePolicy[policy].data.PolicyDocument);
                        if (!statements) break;

                        // Loop through statements to see if admin privileges
                        for (s in statements) {
                            var statement = statements[s];

                            if (statement.Effect === 'Allow' &&
                                !statement.Condition) {
                                var failMsg;
                                var warnMsg;
                                if (statement.Action.indexOf('*') > -1 &&
                                    statement.Resource &&
                                    statement.Resource.indexOf('*') > -1) {
                                    failMsg = 'Role inline policy allows all actions on all resources';
                                } else if (statement.Action.indexOf('*') > -1) {
                                    warnMsg = 'Role inline policy allows all actions on selected resources';
                                } else if (statement.Action && statement.Action.length) {
                                    // Check each action for wildcards
                                    var wildcards = [];
                                    for (a in statement.Action) {
                                        if (statement.Action[a].endsWith(':*')) {
                                            wildcards.push(statement.Action[a]);
                                        }
                                    }
                                    if (wildcards.length) warnMsg = 'Role inline policy allows wildcard actions: ' + wildcards.join(', ');
                                }

                                if (failMsg && roleFailures.indexOf(failMsg) === -1) roleFailures.push(failMsg);
                                if (warnMsg && roleWarnings.indexOf(warnMsg) === -1) roleWarnings.push(warnMsg);
                            }
                        }
                    }
                }
            }

            if (roleFailures.length) {
                helpers.addResult(results, 2,
                    roleFailures.join(', '),
                    'global', role.Arn);
            } else if (roleWarnings.length) {
                helpers.addResult(results, 1,
                    roleWarnings.join(', '),
                    'global', role.Arn);
            } else {
                helpers.addResult(results, 0,
                    'Role does not have overly-permissive policy',
                    'global', role.Arn);
            }

            cb();
        }, function(){
            callback(null, results, source);
        });
    }
};