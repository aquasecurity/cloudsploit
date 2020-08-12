const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Admin Security Alerts Enabled',
    category: 'Security Center',
    description: 'Ensures that security alerts are configured to be sent to admins',
    more_info: 'Enabling security alerts to be sent to admins ensures that detected vulnerabilities and security issues are sent to the subscription admins for quick remediation.',
    recommended_action: 'Ensure that security alerts are configured to be sent to subscription owners.',
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
                if (securityContact.alertsToAdmins &&
                    securityContact.alertsToAdmins.toLowerCase() == 'on') {
                    helpers.addResult(results, 0, 'Security alerts for the subscription are configured to be sent to admins', location, securityContact.id);
                } else {
                    helpers.addResult(results, 2, 'Security alerts for the subscription are not configured to be sent to admins', location, securityContact.id);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
