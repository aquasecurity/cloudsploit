const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Security Defaults Enabled',
    category: 'Entra ID',
    domain: 'Identity and Access Management',
    severity: 'Medium',
    description: 'Ensures that security defaults are enabled in Microsoft Entra ID.',
    more_info: 'Security defaults are preconfigured identity security settings that require all users and administrators to register for multi-factor authentication, challenge users with multi-factor authentication when needed and block legacy authentication protocols. Enabling security defaults provides a basic level of identity protection at no extra cost.',
    recommended_action: 'Enable security defaults from Microsoft Entra ID properties.',
    link: 'https://learn.microsoft.com/en-us/entra/fundamentals/security-defaults',
    apis: ['securityDefaultsPolicy:get'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.securityDefaultsPolicy, function(location, rcb) {

            const policy = helpers.addSource(cache, source,
                ['securityDefaultsPolicy', 'get', location]);

            if (!policy) return rcb();

            if (policy.err || !policy.data) {
                helpers.addResult(results, 3, 'Unable to query for security defaults policy: ' + helpers.addError(policy), location);
                return rcb();
            }

            if (!policy.data.length) {
                helpers.addResult(results, 0, 'No existing security defaults policy found', location);
                return rcb();
            }

            if (policy.data[0].isEnabled) {
                helpers.addResult(results, 0, 'Security defaults are enabled', location);
            } else {
                helpers.addResult(results, 2, 'Security defaults are not enabled', location);
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
