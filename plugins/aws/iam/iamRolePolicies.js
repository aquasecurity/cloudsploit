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
    settings: {
        iam_role_policies_ignore_path: {
            name: 'IAM Role Policies Ignore Path',
            description: 'Ignores roles that contain the provided exact-match path',
            regex: '^[0-9A-Za-z/._-]{3,512}$',
            default: ''
        }
    },

    run: function(cache, settings, callback) {
        var config = {
            iam_role_policies_ignore_path: settings.iam_role_policies_ignore_path || this.settings.iam_role_policies_ignore_path.default
        };

        var custom = helpers.isCustom(settings, this.settings);

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

            // Skip roles with user-defined paths
            if (config.iam_role_policies_ignore_path &&
                config.iam_role_policies_ignore_path.length &&
                role.Path &&
                role.Path.indexOf(config.iam_role_policies_ignore_path) > -1) {
                return cb();
            }

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

            // See if role has admin managed policy
            if (listAttachedRolePolicies &&
                listAttachedRolePolicies.data &&
                listAttachedRolePolicies.data.AttachedPolicies) {

                for (var a in listAttachedRolePolicies.data.AttachedPolicies) {
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

                for (var p in listRolePolicies.data.PolicyNames) {
                    var policyName = listRolePolicies.data.PolicyNames[p];

                    if (getRolePolicy &&
                        getRolePolicy[policyName] && 
                        getRolePolicy[policyName].data &&
                        getRolePolicy[policyName].data.PolicyDocument) {

                        var statements = helpers.normalizePolicyDocument(
                            getRolePolicy[policyName].data.PolicyDocument);
                        if (!statements) break;

                        // Loop through statements to see if admin privileges
                        for (var s in statements) {
                            var statement = statements[s];

                            if (statement.Effect === 'Allow' &&
                                !statement.Condition) {
                                var failMsg;
                                if (statement.Action.indexOf('*') > -1 &&
                                    statement.Resource &&
                                    statement.Resource.indexOf('*') > -1) {
                                    failMsg = 'Role inline policy allows all actions on all resources';
                                } else if (statement.Action.indexOf('*') > -1) {
                                    failMsg = 'Role inline policy allows all actions on selected resources';
                                } else if (statement.Action && statement.Action.length) {
                                    // Check each action for wildcards
                                    var wildcards = [];
                                    for (a in statement.Action) {
                                        if (statement.Action[a].endsWith(':*')) {
                                            wildcards.push(statement.Action[a]);
                                        }
                                    }
                                    if (wildcards.length) failMsg = 'Role inline policy allows wildcard actions: ' + wildcards.join(', ');
                                }

                                if (failMsg && roleFailures.indexOf(failMsg) === -1) roleFailures.push(failMsg);
                            }
                        }
                    }
                }
            }

            if (roleFailures.length) {
                helpers.addResult(results, 2,
                    roleFailures.join(', '),
                    'global', role.Arn, custom);
            } else {
                helpers.addResult(results, 0,
                    'Role does not have overly-permissive policy',
                    'global', role.Arn, custom);
            }

            cb();
        }, function(){
            callback(null, results, source);
        });
    }
};