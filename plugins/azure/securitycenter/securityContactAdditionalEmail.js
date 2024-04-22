const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Security Contact Additional Email',
    category: 'Security Center',
    domain: 'Management and Governance',
    severity: 'Low',
    description: 'Ensure Additional email addresses are configured with security contact email.',
    more_info: 'Microsoft Defender for Cloud emails the Subscription Owner to notify them about security alerts. Adding your Security Contact\'s email address to the Additional email addresses field ensures that your organization\'s Security Team is included in these alerts. This ensures that the proper people are aware of any potential compromise in order to mitigate the risk in a timely fashion.',
    recommended_action: 'Modify security contact information and add additional emails.',
    link: 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/configure-email-notifications',
    apis: ['securityContactv2:listAll'],
    realtime_triggers: ['microsoftsecurity:securitycontacts:write','microsoftsecurity:securitycontacts:delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.securityContacts, (location, rcb) => {

            var securityContacts = helpers.addSource(cache, source,
                ['securityContactv2', 'listAll', location]);

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

            let additionalEmails = securityContacts.data.find(contact => contact.emails && contact.emails.length);

            if (additionalEmails){
                helpers.addResult(results, 0, 'Additional email address is configured with security contact email', location);
            } else {
                helpers.addResult(results, 2, 'Additional email address is not configured with security contact email', location);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
