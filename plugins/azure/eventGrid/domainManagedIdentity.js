const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Event Grid Domain Public Access',
    category: 'Event Grid',
    domain: 'Management and Governance',
    severity: 'Medium',
    description: 'Ensure that Event Grid domains have managed identity enabled.',
    more_info: 'Enabling managed identities eliminate the need for developers having to manage credentials by providing an identity for the Azure resource in Azure AD and using it to obtain Azure Active Directory (Azure AD) tokens.',
    recommended_action: 'Modify Event Grid domains and enable managed identity.',
    link: 'https://learn.microsoft.com/en-us/azure/event-grid/managed-service-identity',
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

                if (domain.identity && domain.identity.type 
                    && (domain.identity.type.toLowerCase() === 'userassigned' || domain.identity.type.toLowerCase() === 'systemassigned')) {
                    helpers.addResult(results, 0, 'Event Grid domain has managed identity enabled', location, domain.id);
                } else {
                    helpers.addResult(results, 2, 'Event Grid domain does not have managed identity enabled', location, domain.id);
                }
            }
            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};