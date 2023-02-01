const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Security Contact Enabled for Subscription Owner',
    category: 'Security Center',
    domain: 'Management and Governance',
    description: 'Ensure that security alert emails are enabled to subscription owners.',
    more_info: 'Enabling security alert emails to subscription owners ensures that they receive security alert emails from Microsoft. This ensures that they are aware of any potential security issues and can mitigate the risk in a timely fashion.',
    recommended_action: 'Modify security contact information and enable emails for subscription owners',
    link: 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/configure-email-notifications',
    apis: ['securityContactv2:listAll'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.securityContactv2, (location, rcb) => {
            
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
            let ownerExists;
            for (let contact of securityContacts.data){
                if (!contact.id) continue;
                if (contact.notificationsByRole && contact.notificationsByRole.roles && contact.notificationsByRole.roles.includes('Owner')){
                    ownerExists = true;
                    break;
                }
            }
            
            if (ownerExists) {
                helpers.addResult(results, 0, 'Security Contact email is configured for subscription owners', location);
            } else {
                helpers.addResult(results, 2, 'Security Contact email is not configured for subscription owners', location);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
