const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Security Contact Additional Email',
    category: 'Security Center',
    domain: 'Management and Governance',
    description: 'Ensure Additional email addresses is Configured with a Security Contact Email',
    more_info: 'Microsoft Defender for Cloud emails the Subscription Owner to notify them about security alerts. Adding your Security Contact\'s email address to the Additional email addresses field ensures that your organization\'s Security Team is included in these alerts. This ensures that the proper people are aware of any potential compromise in order to mitigate the risk in a timely fashion.',
    recommended_action: 'Modify securiyu contact information and add additional email',
    link: 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/configure-email-notifications',
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
            
            for (let contact of securityContacts.data){
                if (!contact.id) continue;

                if (contact.email && contact.email.length > 0){
                    helpers.addResult(results, 0, 'Additional email address is configured with security contact email', location, contact.id);
                } else {
                    helpers.addResult(results, 2, 'Additional email address is not configured with security contact email', location, contact.id);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
