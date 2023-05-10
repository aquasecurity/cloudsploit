const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'High Severity Alerts Enabled',
    category: 'Security Center',
    domain: 'Management and Governance',
    description: 'Ensures that high severity alerts are enabled and properly configured.',
    more_info: 'Enabling high severity alerts ensures that microsoft alerts for potential security issues are sent and allows for quick mitigation of the associated risks.',
    recommended_action: 'Enable email alert notification and configure its severity level.',
    link: 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/configure-email-notifications',
    apis: ['securityContactv2:listAll'],
    settings: {
        minimal_desired_severity_level: {
            name: 'Email alert notification minimal severity level',
            default: 'High',
            description: 'Desired severity level.',
            regex: '^(high|medium|low)$',
        }
    },

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);
        const config = {
            min_desired_severity_level: settings.minimal_desired_severity_level || this.settings.minimal_desired_severity_level.default
        };
        let desiredSeverityLevel = helpers.SEVERITY_LEVELS.indexOf(config.min_desired_severity_level.toLowerCase());
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
                helpers.addResult(results, 2, 'No existing security contacts found', location);
                return rcb();
            }
            for (let contact of securityContacts.data){
                if (!contact.id) continue;

                if ( contact.alertNotifications && contact.alertNotifications.state &&
                contact.alertNotifications.state.toLowerCase() === 'off') {
                    helpers.addResult(results, 2, 'Security contacts email alert notification are not enabled', location, contact.id);
                } else if (contact.alertNotifications.minimalSeverity &&
                helpers.SEVERITY_LEVELS.indexOf(contact.alertNotifications.minimalSeverity.toLowerCase()) >= desiredSeverityLevel){
                    helpers.addResult(results, 0, `Security contacts email alert notifications enabled with minimum severity level
                    ${contact.alertNotifications.minimalSeverity} which is greater or equal to 
                    the desired severity level ${helpers.SEVERITY_LEVELS[desiredSeverityLevel]}`, location, contact.id);
                } else {
                    helpers.addResult(results, 2, `Security contacts email alert notifications enabled with minimum severity 
                    level ${contact.alertNotifications.minimalSeverity} which is less than the desired severity level ${helpers.SEVERITY_LEVELS[desiredSeverityLevel]}`, location);
                }
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
