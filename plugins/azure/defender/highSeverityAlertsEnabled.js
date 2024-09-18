const async = require('async');
const helpers = require('../../../helpers/azure');

const SEVERITY_LEVELS = ['low', 'medium', 'high'];

module.exports = {
    title: 'High Severity Alerts Enabled',
    category: 'Defender',
    domain: 'Management and Governance',
    severity: 'Medium',
    description: 'Ensures that high severity alerts are enabled and properly configured.',
    more_info: 'Enabling high severity alerts ensures that microsoft alerts for potential security issues are sent and allows for quick mitigation of the associated risks.',
    recommended_action: 'Enable email alert notification and configure its severity level.',
    link: 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/configure-email-notifications',
    apis: ['securityContactv2:listAll'],
    settings: {
        alert_notifications_min_severity_level: {
            name: 'Alert Notifications Minimum Severity Level',
            description: 'Security issues severity level for which notifications should be sent. Use "low" option to receive notification for all security issues.',
            regex: '^(high|medium|low)$',
            default: 'medium'
        }
    },
    realtime_triggers: ['microsoftsecurity:securitycontacts:write','microsoftsecurity:securitycontacts:delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        const config = {
            alert_notifications_min_severity_level: settings.alert_notifications_min_severity_level || this.settings.alert_notifications_min_severity_level.default
        };

        let desiredSeverityLevel = SEVERITY_LEVELS.indexOf(config.alert_notifications_min_severity_level.toLowerCase());

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

            for (let contact of securityContacts.data) {
                if (!contact.id) continue;

                if ( contact.alertNotifications && contact.alertNotifications.state &&
                    contact.alertNotifications.state.toLowerCase() === 'off') {
                    helpers.addResult(results, 2, 'Security contacts email alert notification are not enabled', location, contact.id);
                } else {
                    let currentSeverityLevel = contact.alertNotifications.minimalSeverity.toLowerCase();
                    if (contact.alertNotifications.minimalSeverity &&
                        SEVERITY_LEVELS.indexOf(currentSeverityLevel) >= desiredSeverityLevel) {
                        helpers.addResult(results, 0, `Security contacts email alert notifications enabled with minimum severity level
                            ${currentSeverityLevel} which is greater or equal to 
                            the desired severity level ${SEVERITY_LEVELS[desiredSeverityLevel]}`, location, contact.id);
                    } else {
                        helpers.addResult(results, 2, `Security contacts email alert notifications enabled with minimum severity 
                            level ${currentSeverityLevel} which is less than the desired severity level ${SEVERITY_LEVELS[desiredSeverityLevel]}`, location, contact.id);
                    }
                }
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
