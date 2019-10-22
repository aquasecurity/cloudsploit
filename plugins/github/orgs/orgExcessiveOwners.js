var async = require('async');
var helpers = require('../../../helpers/github');

module.exports = {
    title: 'Org Excessive Owners',
    types: ['org'],
    category: 'Orgs',
    description: 'Checks whether the organization has an excessive number of owners relative to its size.',
    more_info: 'Having too many owners of a Git organization increases the risk of a serious compromise from lost credentials.',
    link: 'https://help.github.com/en/articles/permission-levels-for-an-organization',
    recommended_action: 'Reduce the number of owners for the organization and use repository-level permissions for more granular control.',
    apis: ['orgs:listMembers', 'orgs:getMembership'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        var listMembers = helpers.addSource(cache, source,
            ['orgs', 'listMembers']);

        if (!listMembers) return callback(null, results, source);

        if (listMembers.err || !listMembers.data) {
            helpers.addResult(results, 3,
                'Unable to query for organization members: ' + helpers.addError(listMembers));
            return callback(null, results, source);
        }

        var count = {admin: 0, users: 0};

        for (m in listMembers.data) {
            var member = listMembers.data[m];

            var getMembership = helpers.addSource(cache, source,
                ['orgs', 'getMembership', member.login]);

            if (getMembership && getMembership.data && getMembership.data.role) {
                if (getMembership.data.role == 'admin') {
                    count.admin += 1;
                } else {
                    count.users += 1;
                }
            } else {
                helpers.addResult(results, 3,
                    'Unable to get organization membership for user: ' + member.login + ': ' + helpers.addError(getMembership));
            }
        }

        var msg = count.admin + ' owners out of ' + (count.admin + count.users) + ' members.';
        
        if (count.admin + count.users <= 5) {
            helpers.addResult(results, 0,
                'Organization has 5 or fewer users: ' + msg);
        } else {
            var percent = Math.ceil((count.admin/(count.admin + count.users)) * 100);
            if (percent > 20) {
                helpers.addResult(results, 2,
                    'More than 20% of organization users are owners: ' + msg);
            } else {
                helpers.addResult(results, 0,
                    'Less than 20% of organization users are owners: ' + msg);
            }
        }

        callback(null, results, source);
    }
};