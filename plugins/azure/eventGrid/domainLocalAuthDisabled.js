const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Event Grid Domain Local Authentication Disabled',
    category: 'Event Grid',
    domain: 'Management and Governance',
    severity: 'Medium',
    description: 'Ensures that local authentication is disabled for Event Grid domains.',
    more_info: 'For enhanced security, centralized identity management, and seamless integration with Azure\'s authentication and authorization services, it is recommended to rely on Azure Active Directory (Azure AD) and disable local authentication (shared access policies) for Azure Event Grid.',
    recommended_action: 'Ensure that Event Grid domains have local authentication disabled.',
    link: 'https://learn.microsoft.com/en-us/azure/event-grid/authenticate-with-microsoft-entra-id#disable-key-and-shared-access-signature-authentication',
    apis: ['eventGrid:listDomains'],
    realtime_triggers: ['microsofteventgrid:domains:write', 'microsofteventgrid:domains:delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.eventGrid, (location, rcb) => {
            const domains = helpers.addSource(cache, source, 
                ['eventGrid', 'listDomains', location]);

            if (!domains) return rcb();

            if (domains.err || !domains.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Event Grid domains: ' + helpers.addError(domains), location);
                return rcb();
            }

            if (!domains.data.length) {
                helpers.addResult(results, 0, 'No Event Grid domains found', location);
                return rcb();
            }

            for (let domain of domains.data) {
                if (!domain.id) continue;

                if (domain.disableLocalAuth) {
                    helpers.addResult(results, 0, 'Event Grid domain has local authentication disabled', location, domain.id);
                } else {
                    helpers.addResult(results, 2, 'Event Grid domain has local authentication enabled', location, domain.id);
                }
            }
            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};