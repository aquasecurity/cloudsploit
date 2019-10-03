const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Security Contacts Enabled',
    category: 'Security Center',
    description: 'Ensure that security contact phone number and email address is set.',
    more_info: 'By enabling Security Contacts, any vulnerabilities are sent to the contact on file, ensuring quick remediation on any security vulnerabilities and following security best practices.',
    recommended_action: '1. Go to Azure Security Center 2. Select the Pricing & Settings Blade. 3. Click on the Subscription Name 4. Select the Email Notifications Blade 5. Enter the contact information and ensure that Send Email Notification is enabled.',
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

            let phoneExists = false;
            let emailExists = false;
            let subId = '';

            securityContacts.data.forEach(securityContact => {
                var idArr = securityContact.id.split('/');
                idArr.length = idArr.length - 2;
                subId = idArr.join('/');

                if (securityContact.phone) {
                    phoneExists = true;
                };
                if (securityContact.email) {
                    emailExists = true;
                };
            });

            if (phoneExists) {
                helpers.addResult(results, 0, 'Security Contact Phone number is set on the Subscription.', location, subId);
            } else {
                helpers.addResult(results, 2, 'Security Contact Phone number is not set on the Subscription', location, subId);
            };
            if (emailExists) {
                helpers.addResult(results, 0, 'Security Contact Email Address is set on the Subscription.', location, subId);
            } else {
                helpers.addResult(results, 2, 'Security Contact Email Address is not set on the Subscription', location, subId);
            };


            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};