var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'IAM User Without Permissions',
    category: 'IAM',
    domain: 'Identity and Access management',
    description: 'Ensures IAM policies are not connected directly to IAM users',
    more_info: 'To reduce management complexity, IAM permissions should only be assigned to roles and groups. Users can then be added to those groups. Policies should not be applied directly to a user.',
    link: 'http://docs.aws.amazon.com/IAM/latest/UserGuide/best-practices.html#use-groups-for-permissions',
    recommended_action: 'Create groups with the required policies, move the IAM users to the applicable groups, and then remove the inline and directly attached policies from the IAM user.',
    apis: ['IAM:listUsers', 'IAM:listUserPolicies', 'IAM:listAttachedUserPolicies', 'IAM:getPolicyVersion' ,'IAM:listGroupsForUser',
        'IAM:listGroups', 'IAM:listGroupPolicies', 'IAM:listAttachedGroupPolicies'],

    run: function(cache, settings, callback) {
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


            if (listAttachedUserPolicies.err) {
                helpers.addResult(results, 3,
                    'Unable to query for IAM attached policy for user: ' + user.UserName + ': ' + helpers.addError(listAttachedUserPolicies), 'global', user.Arn);
                return cb();
            }

            if (listUserPolicies.err) {
                helpers.addResult(results, 3,
                    'Unable to query for IAM user policy for user: ' + user.UserName + ': ' + helpers.addError(listUserPolicies), 'global', user.Arn);
                return cb();
            }

            if (listGroupsForUser.err) {
                helpers.addResult(results, 3,
                    'Unable to query for IAM groups attached to user: ' + user.UserName + ': ' + helpers.addError(listGroupsForUser), 'global', user.Arn);
                return cb();
            }


            if (!listAttachedUserPolicies.data || !listUserPolicies.data || !listGroupsForUser.data) {
                helpers.addResult(results, 3, 'Unable to query policies for user: ' +
                    user.UserName + ': no data returned', 'global', user.Arn);
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

                    if (listGroupPolicies.data.PolicyNames.length || listAttachedGroupPolicies.data.AttachedPolicies.length ){
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