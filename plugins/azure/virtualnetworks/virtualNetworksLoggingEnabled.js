var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Virtual Networks Logging Enabled',
    category: 'Virtual Networks',
    domain: 'Network Access Control',
    severity: 'Medium',
    description: 'Ensure that Microsoft Virtual Networks have diagnostic logs enabled.',
    more_info: 'Diagnostic logs provide valuable insights into the operation and health of Virtual Networks. By enabling diagnostic logs, you can monitor network traffic, troubleshoot connectivity issues, and gain visibility into network performance.',
    link: 'https://learn.microsoft.com/en-us/azure/virtual-network/monitor-virtual-network',
    recommended_action: 'Modify the virtual network settings and enable diagnostic logs.',
    apis: ['virtualNetworks:listAll', 'diagnosticSettings:listByVirtualNetworks'],
    realtime_triggers: ['microsoftnetwork:virtualnetworks:write','microsoftnetwork:virtualnetworks:delete','microsoftinsights:diagnosticsettings:write','microsoftinsights:diagnosticsettings:delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.virtualNetworks, function(location, rcb){
            var virtualNetworks = helpers.addSource(cache, source, 
                ['virtualNetworks', 'listAll', location]);

            if (!virtualNetworks) return rcb();

            if (virtualNetworks.err || !virtualNetworks.data) {
                helpers.addResult(results, 3, 'Unable to query for Virtual Networks: ' + helpers.addError(virtualNetworks), location);
                return rcb();
            }

            if (!virtualNetworks.data.length) {
                helpers.addResult(results, 0, 'No existing Virtual Networks found', location);
                return rcb();
            }

            for (let vn of virtualNetworks.data) {
                if (!vn.id) continue;

                var diagnosticSettings = helpers.addSource(cache, source, 
                    ['diagnosticSettings', 'listByVirtualNetworks', location, vn.id]);
 
                if (!diagnosticSettings || diagnosticSettings.err || !diagnosticSettings.data) {
                    helpers.addResult(results, 3, `Unable to query for Virtual Network diagnostic settings: ${helpers.addError(diagnosticSettings)}`,
                        location, vn.id);
                    continue;
                }

                var found = diagnosticSettings.data.find(ds => ds.logs && ds.logs.length);

                if (found) {
                    helpers.addResult(results, 0, 'Virtual Network has diagnostic logs enabled', location, vn.id);
                } else {
                    helpers.addResult(results, 2, 'Virtual Network does not have diagnostic logs enabled', location, vn.id);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
