var async = require('async');
var helpers = require('../../../helpers/aws');

var adminAccessArn = 'arn:aws:iam::aws:policy/AdministratorAccess';
var iamFullAccessArn = 'arn:aws:iam::aws:policy/IAMFullAccess';

var iamEditAccessPermissions = [
    'iam:CreatePolicy',
    'iam:CreatePolicyVersion',
    'iam:DeleteGroupPolicy',
    'iam:DeletePolicy',
    'iam:DeletePolicyVersion',
    'iam:DeleteRolePolicy',
    'iam:DeleteUserPolicy',
    'iam:DetachGroupPolicy',
    'iam:DetachRolePolicy',
    'iam:DetachUserPolicy',
    'iam:PutGroupPolicy',
    'iam:PutRolePolicy',
    'iam:PutUserPolicy',
    'iam:UpdateAssumeRolePolicy'
];

module.exports = {
    title: 'IAM User Unauthorized to Edit',
    category: 'IAM',
    description: 'Ensures AWS IAM users that are not authorized to edit IAM access policies are decommissioned.',
    more_info: 'Only authorized IAM users should have permission to edit IAM access policies to prevent any unauthorized requests.',
    link: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/access_controlling.html',
    recommended_action: 'Update unauthorized IAM users to remove permissions to edit IAM access policies.',
    apis: ['IAM:listUsers', 'IAM:listUserPolicies', 'IAM:listAttachedUserPolicies', 'IAM:getUserPolicy'],
    compliance: {
        pci: 'PCI requires that cardholder data can only be accessed by those with ' +
             'a legitimate business need. Limiting the number of IAM administrators ' +
             'reduces the scope of users with potential access to this data.'
    },
    settings: {
        iam_authorized_user_arns: {
            name: 'IAM Authorized User ARNs',
            description: 'A comma delimited list of user ARNs athorized to contain edit IAM access policies permission',
            regex: '^((?:{12}|arn:aws:iam::{12}:(?:root|user[A-Za-z0-9]+)),?*)*',
            default: ''
        }
    },

    run: function(cache, settings, callback) {
        var whitelisted_users = settings.iam_authorized_user_arns || this.settings.iam_authorized_user_arns.default;

        var results = [];
        var source = {};

        var region = helpers.defaultRegion(settings);

        var listUsers = helpers.addSource(cache, source,
            ['iam', 'listUsers', region]);

        if (!listUsers) return callback(null, results, source);

        if (listUsers.err || !listUsers.data) {
            helpers.addResult(results, 3,
                'Unable to query for user IAM policy status: ' + helpers.addError(listUsers));
            return callback(null, results, source);
        }

        if (!helpers.isValidArray(listUsers.data)) {
            helpers.addResult(results, 0, 'No user accounts found');
            return callback(null, results, source);
        }

        async.each(listUsers.data, function(user, cb){
            if (!user.UserName) return cb();

            // Get managed policies attached to user
            var listAttachedUserPolicies = helpers.addSource(cache, source,
                ['iam', 'listAttachedUserPolicies', region, user.UserName]);

            // Get inline policies attached to user
            var listUserPolicies = helpers.addSource(cache, source,
                ['iam', 'listUserPolicies', region, user.UserName]);

            if (!listAttachedUserPolicies || listAttachedUserPolicies.err || !listAttachedUserPolicies.data) {
                helpers.addResult(results, 3,
                    'Unable to query for IAM attached policy for user: ' + user.UserName + ': ' + helpers.addError(listAttachedUserPolicies), 'global', user.Arn);
                return cb();
            }
                
            if (!listUserPolicies || listUserPolicies.err || !listUserPolicies.data) {
                helpers.addResult(results, 3,
                    'Unable to query for IAM user policy for user: ' + user.UserName + ': ' + helpers.addError(listUserPolicies), 'global', user.Arn);
                return cb();
            }
        
            var getUserPolicy = helpers.addSource(cache, source,
                ['iam', 'getUserPolicy', region, user.UserName]);


            var restrictedPermissions = [];

            // See if user has administrator access or IAM full access
            if (listAttachedUserPolicies.data.AttachedPolicies) {

                for (var p in listAttachedUserPolicies.data.AttachedPolicies) {
                    var policy = listAttachedUserPolicies.data.AttachedPolicies[p];

                    if (policy.PolicyArn === adminAccessArn ||
                        policy.PolicyArn === iamFullAccessArn) {
                        restrictedPermissions.push(policy.PolicyName);
                    }
                }
            }

            // See if user has IAM full access inline policy
            if (listUserPolicies.data.PolicyNames) {

                for (var up in listUserPolicies.data.PolicyNames) {
                    var policyName = listUserPolicies.data.PolicyNames[up];

                    if (getUserPolicy &&
                        getUserPolicy[policyName] &&
                        getUserPolicy[policyName].data &&
                        getUserPolicy[policyName].data.PolicyDocument) {

                        var statements = helpers.normalizePolicyDocument(
                            getUserPolicy[policyName].data.PolicyDocument);
                        if (!statements) break;

                        // Loop through statements to see if admin privileges
                        for (var s in statements) {
                            var statement = statements[s];

                            if (statement.Effect === 'Allow' &&
                                (statement.Action.indexOf('iam:*') > -1 ||
                                iamEditAccessPermissions.some(permission=> statement.Action.includes(permission)))) {
                                restrictedPermissions.push(policyName);
                            }
                        }
                    }
                }
            }

            if (!helpers.isValidArray(restrictedPermissions)) {
                helpers.addResult(results, 0,
                    `IAM user "${user.UserName}" does not have or is authorized to have edit access policies permission`,
                    'global', user.Arn);
            } else if (whitelisted_users.includes(user.Arn)) {
                helpers.addResult(results, 0,
                    `IAM user "${user.UserName}" is authorized to have edit access policies permission`,
                    'global', user.Arn);
            } else {
                helpers.addResult(results, 2,
                    `IAM user "${user.UserName}" is not authorized to have these permissions: ${restrictedPermissions.join(', ')}`,
                    'global', user.Arn);
            }

            cb();
        }, function(){
            callback(null, results, source);
        });
    }
};