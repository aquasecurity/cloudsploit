var async = require('async');
var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'Users MFA Enabled',
    category: 'Identity',
    description: 'Ensures a multi-factor authentication device is enabled for all users within the account.',
    more_info: 'User accounts should have an MFA device setup to enable two-factor authentication.',
    link: 'https://docs.oracle.com/en/cloud/paas/identity-cloud/uaids/enable-multi-factor-authentication-security-oracle-cloud.html',
    recommended_action: 'Enable an MFA device for the user account.',
    apis: ['user:list'],
    compliance: {
        hipaa: 'MFA helps provide additional assurance that the user accessing ' +
            'the cloud environment has been identified. HIPAA requires ' +
            'strong controls around entity authentication which can be ' +
            'enhanced through the use of MFA.',
        pci: 'PCI requires MFA for all access to cardholder environments. ' +
            'Create an MFA key for user accounts.'
    },

    run: function (cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings.govcloud);

        async.each(regions.user, function (region, rcb) {

            if (helpers.checkRegionSubscription(cache, source, results, region)) {

                var users = helpers.addSource(cache, source,
                    ['user', 'list', region]);

                if (!users) return rcb();

                if (users.err || !users.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for user MFA status: ' + helpers.addError(users));
                    return rcb();
                }

                if (users.data.length === 1) {
                    helpers.addResult(results, 0, 'No user accounts found');
                    return rcb();
                }

                for (u in users.data) {
                    var user = users.data[u];

                    if (user.isMfaActivated) {
                        helpers.addResult(results, 0,
                            'User: ' + user.name + ' has an MFA device', 'global', user.id);
                    } else {
                        helpers.addResult(results, 1,
                            'User: ' + user.name + ' does not have an MFA device enabled', 'global', user.id);
                    }
                }
            }

            rcb();
        }, function () {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
