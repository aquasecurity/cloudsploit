var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'Users MFA Enabled',
    category: 'Identity',
    domain: 'Identity and Access Management',
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
    setting: {
        warn_federated_users: {
            name: 'Warn Federated Users',
            description: 'Give a WARN instead of FAIL result for federated users',
            regex: '^(true|false)$',
            default: 'false'
        } 
    },

    run: function (cache, settings, callback) {
        var results = [];
        var source = {};
        var config = {
            warn_federated_users: settings.warn_federated_users || this.setting.warn_federated_users.default
        };
        var warnFedUsers = (config.warn_federated_users == 'true');

        var region = helpers.objectFirstKey(cache['regionSubscription']['list']);

            var users = helpers.addSource(cache, source,
                ['user', 'list', region]);

            if (!users) return callback(null, results, source);

            if (users.err || !users.data) {
                helpers.addResult(results, 3,
                    'Unable to query for user MFA status: ' + helpers.addError(users));
                return callback(null, results, source);
            }

            if (users.data.length < 2) {
                helpers.addResult(results, 0, 'No user accounts found');
                return callback(null, results, source);
            }

            users.data.forEach(user => {
                if (user.isMfaActivated) {
                    helpers.addResult(results, 0, 'The user has MFA enabled', 'global', user.id);
                } else {
                    if (user.identityProviderId && user.identityProviderId.length && warnFedUsers) {
                        helpers.addResult(results, 1, 'The federated user has MFA disabled', 'global', user.id);
                    } else helpers.addResult(results, 2, 'The user has MFA disabled', 'global', user.id);
                }
            });

            callback(null, results, source);
    }
};
