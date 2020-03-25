var async = require('async');
var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'Users MFA Enabled',
    category: 'Identity',
    description: 'Ensures a multi-factor authentication device is enabled for all users within the account.',
    more_info: 'User accounts should have an MFA device setup to enable two-factor authentication.',
    link: 'https://docs.cloud.oracle.com/iaas/Content/Identity/Tasks/usingmfa.htm',
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
        var noMFAUsers = [];

        async.each(regions.user, function (region, rcb) {
            var users = helpers.addSource(cache, source,
                ['user', 'list', region]);

            if (!users) return rcb();

            if (users.err || !users.data) {
                helpers.addResult(results, 3,
                    'Unable to query for user MFA status: ' + helpers.addError(users));
                return rcb();
            }

            if (users.data.length < 2) {
                helpers.addResult(results, 0, 'No user accounts found');
                return rcb();
            }

            users.data.forEach(user => {
                if (!user.isMfaActivated) {
                    noMFAUsers.push(user.name)
                }
            });

            rcb();
        }, function () {
            // Global checking goes here
            if (noMFAUsers.length) {
                var noMFAUserStr = noMFAUsers.join(', ');
                helpers.addResult(results, 2,
                    `The following accounts do not have an MFA device enabled: ${noMFAUserStr}`, 'global');
            } else {
                helpers.addResult(results, 0, 'All accounts have MFA enabled.', 'global');
            }
            callback(null, results, source);
        });
    }
};
