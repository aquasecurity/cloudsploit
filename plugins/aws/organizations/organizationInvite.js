var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Organization Invite',
    category: 'Organizations',
    description: 'Ensure all Organization invites are accepted',
    more_info: 'AWS Organizations invites should be accepted or rejected quickly so that member accounts can take advantage of all Organization features.',
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
