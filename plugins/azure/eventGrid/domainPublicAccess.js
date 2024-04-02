const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Event Grid Domain Public Access',
    category: 'Event Grid',
    domain: 'Management and Governance',
    severity: 'Medium',
    description: 'Ensures that Azure Event Grid domains are not publicly accessible.',
    more_info: 'By default, domains are accessible from internet as long as the request comes with valid authentication and authorization exposing sensitive information. By disabling public access, Event Grid domains can be configured to use private endpoint.',
    recommended_action: 'Modify the affected domains and disable public network access.',
    link: 'https://learn.microsoft.com/en-us/azure/event-grid/configure-firewall',
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

                if (domain.publicNetworkAccess && domain.publicNetworkAccess.toLowerCase() === 'enabled') {
                    helpers.addResult(results, 2, 'Event Grid domain has public network access enabled', location, domain.id);
                } else {
                    helpers.addResult(results, 0, 'Event Grid domain does not have public network access enabled', location, domain.id);
                }
            }
            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};