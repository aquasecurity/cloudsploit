var async = require('async');
var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'Empty Groups',
    category: 'Identity',
    description: 'Ensures all groups have at least one member.',
    more_info: 'While having empty groups does not present a direct security risk, it does broaden the management landscape which could potentially introduce risks in the future.',
    link: 'https://docs.oracle.com/cd/E10391_01/doc.910/e10360/usergroups.htm',
    recommended_action: 'Remove identity groups with no members.',
    apis: ['group:list', 'userGroupMembership:list'],

    run: function (cache, settings, callback) {
        var results = [];
        var source = {};
        var defaultRegion = '';

        if (cache.group.list &&
            Object.keys(cache.group.list).length &&
            Object.keys(cache.group.list).length>0){
            defaultRegion = Object.keys(cache.group.list)[0];
        } else {
            return callback();
        }

        var groups = helpers.addSource(cache, source,
            ['group', 'list', defaultRegion]);

        var userGroups = helpers.addSource(cache, source,
            ['userGroupMembership', 'list', defaultRegion]);

        if (!groups || !userGroups) return callback();

        if (((groups.err &&
            groups.err.length &&
            groups.err.length > 0) || !groups.data) ||
            ((userGroups.err &&
                userGroups.err.length &&
                userGroups.err.length > 0) || !userGroups.data)) {
            helpers.addResult(results, 3,
                'Unable to query user groups: ' + helpers.addError(userGroups), region);
            return callback();
        }

        if (!groups.data.length || !userGroups.data.length) {
            helpers.addResult(results, 0, 'No groups found');
            return callback();
        }

        for (g in groups.data) {
            var group = groups.data[g];

            for (ug in userGroups.data) {
                var users = userGroups.data[ug].filter((u) => {
                    return u.groupId == group.id;
                });
                if (users.length && users.length > 0) break;
            }

            if (users &&
                users.length &&
                users.length > 0) {
                helpers.addResult(results, 0, 'Group contains ' + users.length + ' user(s)', defaultRegion, group.name + ' - ' + group.id);
            } else {
                helpers.addResult(results, 1, 'Group does not contain any users', defaultRegion, group.name + ' - ' + group.id)
            }
        }

        callback(null, results, source);
    }
};