const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Attack Path Notifications Enabled',
    category: 'Defender',
    domain: 'Management and Governance',
    severity: 'Low',
    description: 'Ensures that email notifications for attack paths are enabled for the subscription.',
    more_info: 'Enabling attack path email notifications ensures that the subscription owner or other designated security contact is notified of new attack paths detected by Microsoft Defender for Cloud, allowing for quick mitigation of the associated risks.',
    recommended_action: 'Enable email notifications for attack paths from the Microsoft Defender for Cloud email notifications settings.',
    link: 'https://learn.microsoft.com/en-us/azure/defender-for-cloud/configure-email-notifications',
    apis: ['securityContactv3:listAll'],
    realtime_triggers: ['microsoftsecurity:securitycontacts:write', 'microsoftsecurity:securitycontacts:delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.securityContactv3, (location, rcb) => {
            var securityContacts = helpers.addSource(cache, source,
                ['securityContactv3', 'listAll', location]);

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

                var attackPathSource = contact.notificationsSources ?
                    contact.notificationsSources.find(notifSource => notifSource.sourceType &&
                        notifSource.sourceType.toLowerCase() === 'attackpath') : null;

                if (attackPathSource && attackPathSource.minimalRiskLevel) {
                    helpers.addResult(results, 0,
                        `Attack path email notifications are enabled with minimum risk level ${attackPathSource.minimalRiskLevel}`, location, contact.id);
                } else {
                    helpers.addResult(results, 2, 'Attack path email notifications are not enabled', location, contact.id);
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
