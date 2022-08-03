var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'User Customer Secret Keys Rotated',
    category: 'Identity',
    domain: 'Identity and Access Management',
    description: 'Ensure that user customer secret keys are rotated regularly in order to reduce accidental exposures.',
    more_info: 'User customer secret keys should be rotated frequently to avoid having them accidentally exposed.',
    link: 'https://docs.oracle.com/en-us/iaas/Content/Identity/Tasks/managingcredentials.htm',
    recommended_action: 'Rotate user customer secret keys',
    apis: ['user:list', 'customerSecretKey:list'],
    settings: {
        customer_secret_key_rotated_fail: {
            name: 'Customer Secret Keys Rotated Fail',
            description: 'Return a failing result when customer secret keys exceed this number of days without being rotated',
            regex: '^[1-9]{1}[0-9]{0,3}$',
            default: '90'
        }
    },

    run: function (cache, settings, callback) {
        var results = [];
        var source = {};
        var region = helpers.objectFirstKey(cache['regionSubscription']['list']);

        var config = {
            customer_secret_key_rotated_fail: parseInt(settings.customer_secret_key_rotated_fail || this.settings.customer_secret_key_rotated_fail.default)
        }

        var users = helpers.addSource(cache, source,
            ['user', 'list', region]);

        var customerSecretKeys = helpers.addSource(cache, source,
            ['customerSecretKey', 'list', region]);

        if (!users || !customerSecretKeys) return callback(null, results, source);

        if (users.err || !users.data) {
            helpers.addResult(results, 3,
                'Unable to query for users: ' + helpers.addError(users), 'global');
            return callback(null, results, source);
        }

        if (!users.data.length) {
            helpers.addResult(results, 0, 'No user accounts found', 'global');
            return callback(null, results, source);
        }

        if (customerSecretKeys.err || !customerSecretKeys.data) {
            helpers.addResult(results, 3,
                'Unable to query user customer secret keys: ' + helpers.addError(customerSecretKeys), 'global');
            return callback(null, results, source);
        }

        if (!customerSecretKeys.data.length) {
            helpers.addResult(results, 0, 'No user customer secret keys found', 'global');
            return callback(null, results, source);
        }

        for (let csk of customerSecretKeys.data) {
            if (!csk.id) continue;

            let timeCreated = csk.timeCreated ? csk.timeCreated : new Date();
            let difference = helpers.daysBetween(timeCreated, new Date());

            if (difference > config.customer_secret_key_rotated_fail) {
                helpers.addResult(results, 2, `Customer secret key is ${difference} days old`, 'global', csk.id);
            } else {
                helpers.addResult(results, 0, `Customer secret key is ${difference} days old`, 'global', csk.id);
            }
        }

        callback(null, results, source);
    }
};
