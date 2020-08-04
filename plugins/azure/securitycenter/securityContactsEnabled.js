const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Security Contacts Enabled',
    category: 'Security Center',
    description: 'Ensures that security contact phone number and email address are set',
    more_info: 'Setting security contacts ensures that any security incidents detected by Azure are sent to a security team equipped to handle the incident.',
    recommended_action: 'Ensure that email notifications are configured for the subscription from the Security Center.',
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
                if (securityContact.phone) {
                    helpers.addResult(results, 0, 'Security Contact phone number is set on the subscription', location, securityContact.id);
                } else {
                    helpers.addResult(results, 2, 'Security Contact phone number is not set on the subscription', location, securityContact.id);
                }

                if (securityContact.email) {
                    helpers.addResult(results, 0, 'Security Contact email address is set on the subscription', location, securityContact.id);
                } else {
                    helpers.addResult(results, 2, 'Security Contact email address is not set on the subscription', location, securityContact.id);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};