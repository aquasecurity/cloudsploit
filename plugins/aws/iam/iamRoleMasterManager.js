var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'IAM Master and Manager Roles',
    category: 'IAM',
    description: 'Ensure that the IAM administration and permission management within your AWS account is divided between two roles: IAM Master and IAM Manager.',
    more_info: 'The IAM Master role duty is to create IAM users, groups and roles, while the IAM Manager role responsibility is to assign users and roles to groups.',
    link: 'https://d0.awsstatic.com/whitepapers/compliance/AWS_CIS_Foundations_Benchmark.pdf',
    recommended_action: 'Divide account and permission configuration permissions between two roles, IAM Master and IAM Manager',
    apis: ['IAM:listRoles', 'IAM:listRolePolicies', 'IAM:getPolicy', 'IAM:getRolePolicy'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var custom = helpers.isCustom(settings, this.settings);
        var region = helpers.defaultRegion(settings);

        var listRoles = helpers.addSource(cache, source, ['iam', 'listRoles', region]);

        if (!listRoles) return callback(null, results, source);

        if (listRoles.err || !listRoles.data) {
            helpers.addResult(results, 3, 'Unable to query for IAM roles: ' + helpers.addError(listRoles));
            return callback(null, results, source);
        }

        if (!listRoles.data.length) {
            helpers.addResult(results, 0, 'No IAM roles found');
            return callback(null, results, source);
        }

        async.each(listRoles.data, function(role, cb){
            if (!role.RoleName) return cb();

            // Get inline policies attached to role
            var listRolePolicies = helpers.addSource(cache, source, ['iam', 'listRolePolicies', region, role.RoleName]);
            var getRolePolicy = helpers.addSource(cache, source, ['iam', 'getRolePolicy', region, role.RoleName]);

            if (listRolePolicies.err) {
                helpers.addResult(results, 3, 'Unable to query for IAM role policy for role: ' + role.RoleName + ': ' + helpers.addError(listRolePolicies), 'global', role.Arn);
                return cb();
            }

            var isMasterRole, isManagerRole;
            isManagerRole = isMasterRole = false;

            //Define required policies for master/manager
            var requiredMasterAllowPolicies = [ 
                'iam:AttachRolePolicy', 'iam:CreateGroup', 'iam:CreatePolicy', 'iam:CreatePolicyVersion', 'iam:CreateRole ', 'iam:CreateUser ', 
                'iam:DeleteGroup', 'iam:DeletePolicy', 'iam:DeletePolicyVersion', 'iam:DeleteRole', 'iam:DeleteRolePolicy', 'iam:DeleteUser', 'iam:PutRolePolicy', 
                'iam:GetPolicy', 'iam:GetPolicyVersion', 'iam:GetRole', 'iam:GetRolePolicy', 'iam:GetUser', 'iam:GetUserPolicy', 'iam:ListEntitiesForPolicy', 
                'iam:ListGroupPolicies', 'iam:ListGroups', 'iam:ListGroupsForUser', 'iam:ListPolicies', 'iam:ListPoliciesGrantingServiceAccess', 'iam:ListPolicyVersions',
                'iam:ListRolePolicies', 'iam:ListAttachedGroupPolicies', 'iam:ListAttachedRolePolicies', 'iam:ListAttachedUserPolicies', 'iam:ListRoles', 'iam:ListUsers' 
            ];
            var requiredMasterDenyPolicies = [ 
                'iam:AddUserToGroup', 'iam:AttachGroupPolicy', 'iam:DeleteGroupPolicy', 'iam:DeleteUserPolicy', 'iam:DetachGroupPolicy', 'iam:DetachRolePolicy', 'iam:DetachUserPolicy',
                'iam:PutGroupPolicy', 'iam:PutUserPolicy', 'iam:RemoveUserFromGroup', 'iam:UpdateGroup', 'iam:UpdateAssumeRolePolicy', 'iam:UpdateUser' 
            ];

            var requiredManagerAllowPolicies = [ 
                'iam:AddUserToGroup', 'iam:AttachGroupPolicy', 'iam:DeleteGroupPolicy', 'iam:DeleteUserPolicy', 'iam:DetachGroupPolicy', 'iam:DetachRolePolicy', 'iam:DetachUserPolicy', 
                'iam:PutGroupPolicy', 'iam:PutUserPolicy', 'iam:RemoveUserFromGroup', 'iam:UpdateGroup', 'iam:UpdateAssumeRolePolicy', 'iam:UpdateUser', 'iam:GetPolicy', 
                'iam:GetPolicyVersion', 'iam:GetRole', 'iam:GetRolePolicy', 'iam:GetUser', 'iam:GetUserPolicy', 'iam:ListEntitiesForPolicy', 'iam:ListGroupPolicies', 'iam:ListGroups', 
                'iam:ListGroupsForUser', 'iam:ListPolicies', 'iam:ListPoliciesGrantingServiceAccess', 'iam:ListPolicyVersions', 'iam:ListRolePolicies', 'iam:ListAttachedGroupPolicies',
                'iam:ListAttachedRolePolicies', 'iam:ListAttachedUserPolicies', 'iam:ListRoles', 'iam:ListUsers'
            ];
            var requiredManagerDenyPolicies = [ 
                'iam:AddUserToGroup ', 'iam:AttachRolePolicy ', 'iam:CreateGroup ', 'iam:CreatePolicy ', 'iam:CreatePolicyVersion ', 'iam:CreateRole ', 'iam:CreateUser ', 
                'iam:DeleteGroup ', 'iam:DeletePolicy ', 'iam:DeletePolicyVersion ', 'iam:DeleteRole ', 'iam:DeleteRolePolicy ', 'iam:DeleteUser ', 'iam:PutRolePolicy'
            ];

            // See if any roles have the required policies
            if (listRolePolicies && listRolePolicies.data && listRolePolicies.data.PolicyNames) {
                for (var p in listRolePolicies.data.PolicyNames) {
                    var policyName = listRolePolicies.data.PolicyNames[p];

                    if (getRolePolicy &&
                        getRolePolicy[policyName] && 
                        getRolePolicy[policyName].data &&
                        getRolePolicy[policyName].data.PolicyDocument) {

                        var statements = helpers.normalizePolicyDocument(getRolePolicy[policyName].data.PolicyDocument);
                        if (!statements) break;

                        // Check statements to see if they match policies
                        var allowStatements = statements.filter(statement => statement.Effect === 'Allow' && !statement.Condition);
                        var denyStatements = statements.filter(statement => statement.Effect === 'Deny' && !statement.Condition);
                        
                        let sortedAllowActions = allowStatements.flatMap(statement => statement.Action).sort();
                        let sortedDenyActions = denyStatements.flatMap(statement => statement.Action).sort();

                        if (sortedAllowActions.join() === requiredMasterAllowPolicies.sort().join() && sortedDenyActions.join() === requiredMasterDenyPolicies.sort().join()) {
                            isMasterRole = true;
                        }
                        else if(sortedAllowActions.join() === requiredManagerAllowPolicies.sort().join() && sortedDenyActions.join() === requiredManagerDenyPolicies.sort().join()) {
                            isManagerRole = true;
                        }
                    }
                }
            }

            if(isManagerRole && isMasterRole) {
                helpers.addResult(results, 0, 'Master and Manager roles found', 'global', role.Arn, custom);
            }
            else if(isMasterRole){
                helpers.addResult(results, 1, 'Master role exist but Manager role does not', 'global', role.Arn, custom);
            }
            else if(isManagerRole){
                helpers.addResult(results, 1, 'Manager role exist but Master role does not', 'global', role.Arn, custom);
            }
            else{
                helpers.addResult(results, 1, 'Master and Manager roles do not exist', 'global', role.Arn, custom);
            }

            cb();
        }, function(){
            callback(null, results, source);
        });
    }
};