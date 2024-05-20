var async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Event Grid Domain Minimum TLS Version',
    category: 'Event Grid',
    domain: 'Management and Governance',
    severity: 'Medium',
    description: 'Ensures that Azure Event Grid domain is using the latest TLS version.',
    more_info: 'Using latest TLS version for Event Grid domains enforces strict security measures, which requires that clients send and receive data with a newer version of TLS. Azure Event Grid uses TLS 1.2 on public endpoints by default.',
    recommended_action: 'Ensure that Event Grid domain is using latest TLS version.',
    link: 'https://learn.microsoft.com/en-us/azure/event-grid/transport-layer-security-configure-minimum-version',
    apis: ['eventGrid:listDomains'],
    realtime_triggers: ['microsofteventgrid:domains:write', 'microsofteventgrid:domains:delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);
        const tlsVersion = 1.2;

        async.each(locations.eventGrid, function(location, rcb) {
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

            for (let domain of domains.data){
                if (!domain.id) continue;
                
                if (domain.minimumTlsVersionAllowed && parseFloat(domain.minimumTlsVersionAllowed) >= tlsVersion) {
                    helpers.addResult(results, 0,
                        `Event Grid domain is using latest TLS version: ${domain.minimumTlsVersionAllowed}`,
                        location, domain.id);
                } else {
                    helpers.addResult(results, 2,
                        `Event Grid domain is not using latest TLS version of ${tlsVersion}`,
                        location, domain.id);
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
