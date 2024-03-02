var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Bastion Host Diagnostic Logs Enabled',
    category: 'Bastion',
    domain: 'Compute',
    severity: 'Medium',
    description: 'Ensures that diagnostic logging is enabled for Azure Bastion Host.',
    more_info: 'Enabling diagnostics logs for Azure Bastion helps to monitor user connections, tracking access to workloads, and identifying potential security threats, providing essential insights for effective management and security of your environment.',
    recommended_action: 'Enable diagnostic logging for all Bastion Hosts.',
    link: 'https://learn.microsoft.com/en-us/azure/bastion/diagnostic-logs',
    apis: ['bastionHosts:listAll','diagnosticSettings:listByBastionHosts'],
    realtime_triggers: ['microsoftnetwork:bastionhosts:write','microsoftnetwork:bastionhosts:delete','microsoftinsights:diagnosticsettings:write','microsoftinsights:diagnosticsettings:delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.bastionHosts, function(location, rcb){
            let bastionHost = helpers.addSource(cache, source, 
                ['bastionHosts', 'listAll', location]);

            if (!bastionHost) return rcb();

            if (bastionHost.err || !bastionHost.data) {
                helpers.addResult(results, 3, 'Unable to query for bastion host: ' + helpers.addError(bastionHost), location);
                return rcb();
            }

            if (!bastionHost.data.length) {
                helpers.addResult(results, 0, 'No existing Bastion Hosts found', location);
                return rcb();
            }

            for (let host of bastionHost.data) {
                if (!host.id) continue;

                const diagnosticSettings = helpers.addSource(cache, source,
                    ['diagnosticSettings', 'listByBastionHosts', location, host.id]);

                if (!diagnosticSettings || diagnosticSettings.err || !diagnosticSettings.data) {
                    helpers.addResult(results, 3, `Unable to query for Bastion Host diagnostic settings: ${helpers.addError(diagnosticSettings)}`,
                        location, host.id);
                    continue;
                }
    
                var found = diagnosticSettings.data.find(ds => ds.logs && ds.logs.length);
    
                if (found) {
                    helpers.addResult(results, 0, 'Bastion Host has diagnostic logs enabled', location, host.id);
                } else {
                    helpers.addResult(results, 2, 'Bastion Host does not have diagnostic logs enabled', location, host.id);
                }        
            }
           
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
}; 