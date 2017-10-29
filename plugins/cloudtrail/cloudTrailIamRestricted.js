var async = require('async');
var helpers = require('../../helpers');
module.exports = {
    title: 'CloudTrail IAM Restricted',
    category: 'CloudTrail',
    description: 'Ensures IAM policies used by users, groups, and  \
                  roles do not allow access to CloudTrail.',
    more_info: 'CloudTrail access should be restricted to select few \
                administrators or the root account. Users and roles \
                should not have access to make changes to CloudTrail \
                configurations.',
    link: 'http://docs.aws.amazon.com/awscloudtrail/latest/userguide/\
           control-user-permissions-for-cloudtrail.html',
    recommended_action: 'Modify the autoscaling instance to enable \
                         scaling across multiple availability zones.',
    apis: ['IAM:listUsers', 'IAM:listGroupsForUser', 'IAM:listAttachedGroupPolicies'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var region = 'us-east-1';

        var listUsers = helpers.addSource(cache, source,
                ['iam', 'listUsers', region]);

        if (!listUsers) return callback(null, results, source);

        if (listUsers.err || !listUsers.data) {
            helpers.addResult(results, 3,
                'Unable to query for IAM user: ' + helpers.addError(listUsers));
            return callback(null, results, source);
        }

        if (!listUsers.data.length) {
            helpers.addResult(results, 0, 'No user accounts found');
            return callback(null, results, source);
        }
        listUsers.data.forEach(function(user){
            var listGroupsForUser = helpers.addSource(cache, source,
                ['iam', 'listGroupsForUser', region, user.UserName]);
            console.log(listGroupsForUser)

            var listAttachedGroupPolicies = helpers.addSource(cache, source,
                ['iam', 'listAttachedGroupPolicies', region, user.UserName]);
            console.log(listAttachedGroupPolicies);
            debugger;

        });

    }
};