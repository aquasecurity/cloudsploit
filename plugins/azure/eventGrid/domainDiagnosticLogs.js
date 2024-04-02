const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Event Grid Domain Diagnostic Logs',
    category: 'Event Grid',
    domain: 'Management and Governance',
    severity: 'Medium',
    description: 'Ensures that Azure Event Grid domain has diagnostic logs enabled.',
    more_info: 'Enabling diagnostics logs for Event Grid Domains helps to allow and capture failures and detailed information about events, their sources, and the health of the Event Grid service.This helps identifying potential security threats, providing essential insights for effective management and security of your environment.',
    recommended_action: 'Enable diagnostic logs for all the Event Grid domains.',
    link: 'https://learn.microsoft.com/en-us/azure/event-grid/enable-diagnostic-logs-topic',
    apis: ['eventGrid:listDomains','diagnosticSettings:listByEventGridDomains'],
    realtime_triggers: ['microsofteventgrid:domains:write', 'microsofteventgrid:domains:delete','microsoftinsights:diagnosticsettings:write','microsoftinsights:diagnosticsettings:delete'],

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

                const diagnosticSettings = helpers.addSource(cache, source,
                    ['diagnosticSettings', 'listByEventGridDomains', location, domain.id]);

                if (!diagnosticSettings || diagnosticSettings.err || !diagnosticSettings.data) {
                    helpers.addResult(results, 3, `Unable to query for Event Grid domains diagnostic settings: ${helpers.addError(diagnosticSettings)}`,
                        location, domain.id);
                    continue;
                }
    
                var found = diagnosticSettings.data.find(ds => ds.logs && ds.logs.length);
    
                if (found) {
                    helpers.addResult(results, 0, 'Event Grid domain has diagnostic logs enabled', location, domain.id);
                } else {
                    helpers.addResult(results, 2, 'Event Grid domain does not have diagnostic logs enabled', location, domain.id);
                }    
            }
            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};