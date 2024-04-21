const async = require('async');
const helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'NSG Flow Logs Enabled',
    category: 'Network Security Groups',
    domain: 'Management and Governance',
    severity: 'Medium',
    description: 'Ensures that Azure Network Security Groups have flows log enabled.',
    more_info: 'Enabling NSG flow logs is crucial for maintaining a secure and optimized cloud environment. It provides the necessary visibility, monitoring capabilities, and data for optimizing resources by ensuring compliance, detecting intrusions, and responding effectively to network-related incidents.',
    recommended_action: 'Enable flow logs for each Network Security Group.',
    link: 'https://learn.microsoft.com/en-us/azure/network-watcher/network-watcher-nsg-flow-logging-overview',
    apis: ['networkSecurityGroups:listAll'],
    realtime_triggers: ['microsoftnetwork:networksecuritygroups:write','microsoftnetwork:networksecuritygroups:delete','microsoftinsights:extendeddiagnosticsettings:write','microsoftinsights:extendeddiagnosticsettings:delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.networkSecurityGroups, function(location, rcb) {
            const networkSecurityGroups = helpers.addSource(cache, source,
                ['networkSecurityGroups', 'listAll', location]);

            if (!networkSecurityGroups) return rcb();

            if (networkSecurityGroups.err || !networkSecurityGroups.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Network Security Groups: ' + helpers.addError(networkSecurityGroups), location);
                return rcb();
            }

            if (!networkSecurityGroups.data.length) {
                helpers.addResult(results, 0, 'No existing Network Security Groups found', location);
                return rcb();
            }

            networkSecurityGroups.data.forEach(function(nsg) {

                if (nsg.flowLogs && nsg.flowLogs.length) {
                    helpers.addResult(results, 0, 'Network Security Group has flow logs enabled', location, nsg.id);
                }  else {
                    helpers.addResult(results, 2, 'Network Security Group does not have flow logs enabled', location, nsg.id);
                }

            });
            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
