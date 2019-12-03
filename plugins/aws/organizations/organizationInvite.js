var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Organization Invite',
    category: 'Organizations',
    description: 'Ensure all Organization invites are accepted',
    recommended_action: 'Enable all AWS Organizations features',
    link: 'https://docs.aws.amazon.com/organizations/latest/userguide/orgs_manage_org_support-all-features.html?icmpid=docs_orgs_console',
    apis: ['Organizations:listHandshakesForAccount'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var region = helpers.defaultRegion(settings);
        var listHandshakesForAccount = helpers.addSource(cache, source, ['organizations', 'listHandshakesForAccount', region]);

        if (!listHandshakesForAccount.data || listHandshakesForAccount.err) {
            helpers.addResult(results, 3, 'Cannot list organization handshakes', 'global');
            return callback(null, results, source);
        }

        var invalidHandshakes = listHandshakesForAccount.data.filter(handshake => handshake.State === 'OPEN' && handshake.Action === 'INVITE');

        if (!invalidHandshakes.length) {
            helpers.addResult(results, 0, 'No pending organization invitations', 'global');
        } else {
            for (let invalidHandshake of invalidHandshakes) {
                helpers.addResult(results, 2, 'Unaccepted pending organization invitations', 'global', invalidHandshake.Arn);
            }
        }

        callback(null, results, source);
    }
};
