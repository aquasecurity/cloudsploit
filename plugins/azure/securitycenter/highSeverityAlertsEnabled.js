const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'High Severity Alerts Enabled',
    category: 'Security Center',
    description: 'Ensures that high severity alerts are properly configured.',
    more_info: 'Enabling high severity alerts ensures that microsoft alerts for potential security issues are sent and allows for quick mitigation of the associated risks.',
    recommended_action: 'Ensure that high severity alerts are configured to be sent.',
    link: 'https://docs.microsoft.com/en-us/azure/security-center/security-center-provide-security-contact-details',
    apis: ['securityContacts:list'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.securityContacts, (location, rcb) => {

            var securityContacts = helpers.addSource(cache, source,
                ['securityContacts', 'list', location]);

            if (!securityContacts) return rcb();

            if (securityContacts.err || !securityContacts.data) {
                helpers.addResult(results, 3,
                    'Unable to query for security contacts: ' + helpers.addError(securityContacts), location);
                return rcb();
            }

            if (!securityContacts.data.length) {
                helpers.addResult(results, 2, 'No existing security contacts', location);
                return rcb();
            }

            securityContacts.data.forEach(securityContact => {
                if (securityContact.alertNotifications &&
                    securityContact.alertNotifications.toLowerCase() == 'on') {
                    helpers.addResult(results, 0, 'High severity alerts for the subscription are configured', location, securityContact.id);
                } else {
                    helpers.addResult(results, 2, 'High severity alerts for the subscription are not configured', location, securityContacts.id);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
