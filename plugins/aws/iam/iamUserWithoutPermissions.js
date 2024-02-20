var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'IAM User Without Permissions',
    category: 'IAM',
    domain: 'Identity and Access Management',
    severity: 'Medium',
    description: 'Ensure that no IAM user exists without any permissions.',
    more_info: 'IAM users are created to perform any Console, CLI or API based operations on AWS cloud accounts. They are associated with policies that grant them permissions to perform required operations. An IAM user without any permission is a security risk, it is recommended to either add required permissions or delete them to adhere to compliance standards.',
    link: 'https://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html',
    recommended_action: 'Modify IAM user and attach new permissions or delete the user.',
    apis: ['IAM:listUsers', 'IAM:listUserPolicies', 'IAM:listAttachedUserPolicies', 'IAM:getPolicyVersion' ,'IAM:listGroupsForUser',
        'IAM:listGroups', 'IAM:listGroupPolicies', 'IAM:listAttachedGroupPolicies'],
    realtime_triggers: ['iam:CreateUser','iam:DeleteUser','iam:AttachUserPolicy','iam:DetachUserPolicy','iam:PutUserPolicy','iam:DeleteUserPolicy','iam:PutGroupPolicy','iam:DeleteGroupPolicy','iam:CreateGroup','iam:DeleteGroup','iam:AddUserToGroup','iam:RemoveUserFromGroup','iam:AttachGroupPolicy','iam:DetachGroupPolicy'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        
        var region = helpers.defaultRegion(settings);

        var listUsers = helpers.addSource(cache, source,
            ['iam', 'listUsers', region]);

        if (!listUsers) return callback(null, results, source);

        if (listUsers.err || !listUsers.data) {
            helpers.addResult(results, 3,
                'Unable to query list IAM users: ' + helpers.addError(listUsers));
            return callback(null, results, source);
        }

        if (!listUsers.data.length) {
            helpers.addResult(results, 0, 'No user accounts found');
            return callback(null, results, source);
        }
        
        async.each(listUsers.data, function(user, cb){
            if (!user.UserName) return cb();

            var listAttachedUserPolicies = helpers.addSource(cache, source,
                ['iam', 'listAttachedUserPolicies', region, user.UserName]);

            var listUserPolicies = helpers.addSource(cache, source,
                ['iam', 'listUserPolicies', region, user.UserName]);

            var listGroupsForUser = helpers.addSource(cache, source,
                ['iam', 'listGroupsForUser', region, user.UserName]);

            if (!listAttachedUserPolicies) return cb();
            if (!listUserPolicies) return cb();
            if (!listGroupsForUser) return cb();


            if (listAttachedUserPolicies.err || !listAttachedUserPolicies.data) {
                helpers.addResult(results, 3,
                    'Unable to query for IAM attached policy for user: ' + user.UserName + ': ' + helpers.addError(listAttachedUserPolicies), 'global', user.Arn);
                return cb();
            }

            if (listUserPolicies.err || !listUserPolicies.data) {
                helpers.addResult(results, 3,
                    'Unable to query for IAM policy for user: ' + user.UserName + ': ' + helpers.addError(listUserPolicies), 'global', user.Arn);
                return cb();
            }

            if (listGroupsForUser.err || !listGroupsForUser.data) {
                helpers.addResult(results, 3,
                    'Unable to query for IAM groups attached to user: ' + user.UserName + ': ' + helpers.addError(listGroupsForUser), 'global', user.Arn);
                return cb();
            }

            var listGroupPolicies, listAttachedGroupPolicies;
            if (listGroupsForUser.data && listGroupsForUser.data.Groups){
                for (let group of listGroupsForUser.data.Groups){
                    listGroupPolicies = helpers.addSource(cache, source,
                        ['iam', 'listGroupPolicies', region, group.GroupName]);
                    
                    listAttachedGroupPolicies = helpers.addSource(cache, source,
                        ['iam', 'listAttachedGroupPolicies', region, group.GroupName]);

                    if (!listGroupPolicies || listGroupPolicies.err || !listGroupPolicies.data) {
                        helpers.addResult(results, 3,
                            'Unable to query for IAM group policies: ' + helpers.addError(listGroupPolicies));
                        return cb();
                    }

                    if (!listAttachedGroupPolicies || listAttachedGroupPolicies.err || !listAttachedGroupPolicies.data ) {
                        helpers.addResult(results, 3,
                            'Unable to query for IAM attached group policies: ' + helpers.addError(listAttachedGroupPolicies));
                        return cb();
                    }

                    if ((listGroupPolicies.data.PolicyNames && listGroupPolicies.data.PolicyNames.length) || 
                        (listAttachedGroupPolicies.data.AttachedPolicies && listAttachedGroupPolicies.data.AttachedPolicies.length)){
                        break;
                    }
                }
            }

            if ((listAttachedUserPolicies.data.AttachedPolicies &&
                listAttachedUserPolicies.data.AttachedPolicies.length) ||
               (listUserPolicies.data.PolicyNames &&
                listUserPolicies.data.PolicyNames.length) || (listAttachedGroupPolicies && listAttachedGroupPolicies.data.AttachedPolicies && 
                listAttachedGroupPolicies.data.AttachedPolicies.length) ||
                (listGroupPolicies && listGroupPolicies.data.PolicyNames && listGroupPolicies.data.PolicyNames.length)) {
                helpers.addResult(results, 0, 'IAM user has permissions', 'global', user.Arn);
            } else {
                helpers.addResult(results, 2, 'IAM user does not have any permissions', 'global', user.Arn);
            }

            cb();
        }, function(){
            callback(null, results, source);
        });
    }
};