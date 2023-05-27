const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Domain Public Access',
    category: 'Event Grid',
    domain: 'Messaging services',
    description: 'Ensure that Azure Event Grid domains do not have public access enabled.',
    more_info: 'Enabling public access for Event Grid domains can expose sensitive information and increase the risk of unauthorized access.',
    recommended_action: 'Modify the affected domain and disable public network access.',
    link: 'https://learn.microsoft.com/en-us/azure/event-grid/configure-firewall',
    apis: ['eventGrid:listDomains'],

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