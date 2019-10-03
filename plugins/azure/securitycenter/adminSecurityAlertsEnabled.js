const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Admin Security Alerts Enabled',
    category: 'Security Center',
    description: 'Ensure that security alerts are sent to admins.',
    more_info: 'By enabling Security alerts to admins, any vulnerabilities are sent to the subscription admins, ensuring quick remediation on any security vulnerabilities and following security best practices.',
    recommended_action: '1. Go to Azure Security Center 2. Select the Pricing & Settings Blade. 3. Click on the Subscription Name 4. Select the Email Notifications Blade 5. Ensure that Also send email notification to subscription owners is enabled.',
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
                    'Unable to query security contacts: ' + helpers.addError(securityContacts), location);
                return rcb();
            };

            if (!securityContacts.data.length) {
                helpers.addResult(results, 2, 'No existing security contacts', location);
                return rcb();
            };

            let alertExists = false;
            
            securityContacts.data.forEach(securityContact => {
                var idArr = securityContact.id.split('/');
                idArr.length = idArr.length - 2;
                subId = idArr.join('/');

                if (securityContact.alertsToAdmins == 'On') {
                    alertExists = true;
                };
            });

            if (alertExists) {
                helpers.addResult(results, 0, 'Security alerts to admin for Subscription is enabled', location, subId);
            } else {
                helpers.addResult(results, 2, 'Security alerts to admin for Subscription is not enabled', location, subId);
            };
            

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
