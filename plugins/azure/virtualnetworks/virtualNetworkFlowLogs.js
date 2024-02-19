const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'VNET Flow Logs Enabled',
    category: 'Virtual Networks',
    domain: 'Network Access Control',
    severity: 'Medium',
    description: 'Ensures that Microsoft Azure Virtual Network has flow logs enabled.',
    more_info: 'Enabling flow logs for Microsoft Azure Virtual Networks is essential for comprehensive network visibility, security enhancement, and optimizing resources by providing detailed insights into traffic patterns and potential threats.',
    recommended_action: 'Modify virtual networks and enable flow logs.',
    link: 'https://learn.microsoft.com/en-us/azure/network-watcher/vnet-flow-logs-overview',
    apis: ['virtualNetworks:listAll'],
    realtime_triggers: ['microsoftnetwork:virtualnetworks:write','microsoftnetwork:virtualnetworks:delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.virtualNetworks, (location, rcb) => {
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
            
            for (let virtualNetwork of virtualNetworks.data) {
                if (!virtualNetwork.id) continue;

                if (virtualNetwork.flowLogs && virtualNetwork.flowLogs.length){
                    helpers.addResult(results, 0, 'Virtual Network has flow logs enabled', location, virtualNetwork.id);
                } else {
                    helpers.addResult(results, 2, 'Virtual Network does not have flow logs enabled', location, virtualNetwork.id);
                } 
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
