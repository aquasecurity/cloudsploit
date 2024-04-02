var async = require('async');
var helpers = require('../../../helpers/aws');

const managerRoleActions = {
    allow: [
        'iam:GetRole',
        'iam:GetUser',
        'iam:GetPolicy',
        'iam:ListRoles',
        'iam:ListUsers',
        'iam:ListGroups',
        'iam:UpdateUser',
        'iam:UpdateGroup',
        'iam:ListPolicies',
        'iam:GetRolePolicy',
        'iam:GetUserPolicy',
        'iam:PutUserPolicy',
        'iam:AddUserToGroup',
        'iam:PutGroupPolicy',
        'iam:DeleteUserPolicy',
        'iam:DetachRolePolicy',
        'iam:DetachUserPolicy',
        'iam:GetPolicyVersion',
        'iam:ListRolePolicies',
        'iam:AttachGroupPolicy',
        'iam:DeleteGroupPolicy',
        'iam:DetachGroupPolicy',
        'iam:ListGroupPolicies',
        'iam:ListGroupsForUser',
        'iam:ListPolicyVersions',
        'iam:RemoveUserFromGroup',
        'iam:ListEntitiesForPolicy',
        'iam:UpdateAssumeRolePolicy',
        'iam:ListAttachedRolePolicies',
        'iam:ListAttachedUserPolicies',
        'iam:ListAttachedGroupPolicies',
        'iam:ListPoliciesGrantingServiceAccess'
    ],
    deny: [
        'iam:CreateRole',
        'iam:CreateUser',
        'iam:DeleteRole',
        'iam:DeleteUser',
        'iam:CreateGroup',
        'iam:DeleteGroup',
        'iam:CreatePolicy',
        'iam:DeletePolicy',
        'iam:PutRolePolicy',
        'iam:AddUserToGroup',
        'iam:AttachRolePolicy',
        'iam:DeleteRolePolicy',
        'iam:CreatePolicyVersion',
        'iam:DeletePolicyVersion'
    ]
};

const masterRoleActions = {
    allow: [
        'iam:GetRole',
        'iam:GetUser',
        'iam:GetPolicy',
        'iam:ListRoles',
        'iam:ListUsers',
        'iam:CreateRole',
        'iam:CreateUser',
        'iam:DeleteRole',
        'iam:DeleteUser',
        'iam:ListGroups',
        'iam:CreateGroup',
        'iam:DeleteGroup',
        'iam:CreatePolicy',
        'iam:DeletePolicy',
        'iam:ListPolicies',
        'iam:GetRolePolicy',
        'iam:PutRolePolicy',
        'iam:GetUserPolicy',
        'iam:AttachRolePolicy',
        'iam:DeleteRolePolicy',
        'iam:GetPolicyVersion',
        'iam:ListRolePolicies',
        'iam:ListGroupsForUser',
        'iam:ListGroupPolicies',
        'iam:ListPolicyVersions',
        'iam:CreatePolicyVersion',
        'iam:DeletePolicyVersion',
        'iam:ListEntitiesForPolicy',
        'iam:ListAttachedRolePolicies',
        'iam:ListAttachedUserPolicies',
        'iam:ListAttachedGroupPolicies',
        'iam:ListPoliciesGrantingServiceAccess'
    ],
    deny: [    
        'iam:UpdateUser',
        'iam:UpdateGroup',
        'iam:PutUserPolicy',
        'iam:AddUserToGroup',
        'iam:PutGroupPolicy',
        'iam:DeleteUserPolicy',
        'iam:DetachRolePolicy',
        'iam:DetachUserPolicy',
        'iam:AttachGroupPolicy',
        'iam:DeleteGroupPolicy',
        'iam:DetachGroupPolicy',
        'iam:RemoveUserFromGroup',
        'iam:UpdateAssumeRolePolicy'
    ]
};

module.exports = {
    title: 'IAM Master and IAM Manager Roles',
    category: 'IAM',
    domain: 'Identity and Access Management',
    severity: 'High',
    description: 'Ensure IAM Master and IAM Manager roles are active within your AWS account.',
    more_info: 'IAM roles should be split into IAM Master and IAM Manager roles to work in two-person rule manner for best prectices.',
    link: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles.html',
    recommended_action: 'Create the IAM Master and IAM Manager roles for an efficient IAM administration and permission management within your AWS account',
    apis: ['IAM:listRoles', 'IAM:listRolePolicies', 'IAM:getRolePolicy', 'IAM:getRole'],
    settings: {
        iam_role_policies_ignore_path: {
            name: 'IAM Role Policies Ignore Path',
            description: 'Ignores roles that contain the provided exact-match path',
            regex: '^[0-9A-Za-z/._-]{3,512}$',
            default: false
        },
        iam_role_policies_ignore_tag: {
            name: 'IAM Role Policies Ignore Tag',
            description: 'Ignores roles that contain the provided tag. Give key-value pair i.e. env:Finance',
            regex: '^.*$',
            default: ''
        }
    },
    realtime_triggers: ['iam:CreateRole','iam:DeleteRole'],

    run: function(cache, settings, callback) {
        var config = {
            iam_role_policies_ignore_path: settings.iam_role_policies_ignore_path || this.settings.iam_role_policies_ignore_path.default,
            iam_role_policies_ignore_tag: settings.iam_role_policies_ignore_tag || this.settings.iam_role_policies_ignore_tag.default
        };
        
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

        var masterRoleFound = false;
        var managerRoleFound = false;

        async.each(listRoles.data, function(role, cb){
            if (!role.RoleName || !role.AssumeRolePolicyDocument) return cb();

            // Skip roles with user-defined paths
            if (config.iam_role_policies_ignore_path &&
                config.iam_role_policies_ignore_path.length &&
                role.Path &&
                role.Path.indexOf(config.iam_role_policies_ignore_path) > -1) {
                return cb();
            }

            // Get role details
            var getRole = helpers.addSource(cache, source,
                ['iam', 'getRole', region, role.RoleName]);
                
            if (!getRole || getRole.err || !getRole.data || !getRole.data.Role) {
                helpers.addResult(results, 3,
                    'Unable to query for IAM roles details: ' + role.RoleName + ': ' + helpers.addError(getRole), 'global', role.Arn);
                return cb();
            }

            //Skip roles with user defined tags
            if (config.iam_role_policies_ignore_tag && config.iam_role_policies_ignore_tag.length) {
                if (config.iam_role_policies_ignore_tag.split(':').length == 2){
                    var key = config.iam_role_policies_ignore_tag.split(':')[0].trim();
                    var value= new RegExp(config.iam_role_policies_ignore_tag.split(':')[1].trim());
                    if (getRole.data.Role.Tags && getRole.data.Role.Tags.length){
                        if (getRole.data.Role.Tags.find(tag =>
                            tag.Key == key && value.test(tag.Value))) return cb();
                    }
                }
            }

            // Get inline policies attached to role
            var listRolePolicies = helpers.addSource(cache, source,
                ['iam', 'listRolePolicies', region, role.RoleName]);

            var getRolePolicy = helpers.addSource(cache, source,
                ['iam', 'getRolePolicy', region, role.RoleName]);

            if (listRolePolicies.err || !listRolePolicies.data || !listRolePolicies.data.PolicyNames) {
                helpers.addResult(results, 3,
                    'Unable to query for IAM role policy for role: ' + role.RoleName + ': ' + helpers.addError(listRolePolicies), 'global', role.Arn);
                return cb();
            }

            var assumeRolePolicy = helpers.normalizePolicyDocument(role.AssumeRolePolicyDocument);

            if (!assumeRolePolicy || !assumeRolePolicy.length) return cb();

            var roleAssumable = false;
            for (var a in assumeRolePolicy) {
                var policyStatement = assumeRolePolicy[a];

                if (policyStatement.Effect &&
                    policyStatement.Effect.toUpperCase() === 'ALLOW' &&
                    policyStatement.Action &&
                    policyStatement.Action.indexOf('sts:AssumeRole') > -1 &&
                    policyStatement.Principal &&
                    policyStatement.Principal.Service &&
                    policyStatement.Principal.Service.indexOf('iam.amazonaws.com') > -1) {
                    roleAssumable = true;
                    break;
                }
            }

            if (!roleAssumable) return cb();

            var rolePermissions = { allow: [], deny: [] };

            for (var p in listRolePolicies.data.PolicyNames) {
                var policyName = listRolePolicies.data.PolicyNames[p];

                if (getRolePolicy &&
                    getRolePolicy[policyName] && 
                    getRolePolicy[policyName].data &&
                    getRolePolicy[policyName].data.PolicyDocument) {

                    var statements = getRolePolicy[policyName].data.PolicyDocument;
                    if (!statements) break;

                    for (var s in statements) {
                        var statement = statements[s];
                        if (statement.Action && statement.Action.length && !statement.Condition) {
                            if (statement.Effect && statement.Effect.toUpperCase() === 'ALLOW') {
                                statement.Action.forEach(perm => {
                                    if (!rolePermissions.allow.includes(perm)) rolePermissions.allow.push(perm);
                                });
                                continue;
                            }

                            if (statement.Effect && statement.Effect.toUpperCase() === 'DENY') {
                                statement.Action.forEach(perm => {
                                    if (!rolePermissions.deny.includes(perm)) rolePermissions.deny.push(perm);
                                });
                            }
                        }
                    }
                }
            }

            if (masterRoleActions.allow.every(permission => rolePermissions.allow.includes(permission)) &&
                masterRoleActions.deny.every(permission => rolePermissions.deny.includes(permission))) {
                masterRoleFound = true;
            }

            if (managerRoleActions.allow.every(permission => rolePermissions.allow.includes(permission)) &&
                managerRoleActions.deny.every(permission => rolePermissions.deny.includes(permission))) {
                managerRoleFound = true;
            }

            cb();
        }, function(){
            if (managerRoleFound && masterRoleFound) {
                helpers.addResult(results, 0,
                    'IAM Master and Manager Roles found', 'global');
            } else if (!managerRoleFound && !masterRoleFound) {
                helpers.addResult(results, 2,
                    'IAM Master and Manager Roles not found', 'global');
            } else if (!managerRoleFound) {
                helpers.addResult(results, 2,
                    'IAM Manager Role not found', 'global');
            } else {
                helpers.addResult(results, 2,
                    'IAM Master Role not found', 'global');
            }

            callback(null, results, source);
        });
    }
};