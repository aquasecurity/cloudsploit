const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'VNET Flow Logs Enabled',
    category: 'Virtual Networks',
    domain: 'Network Access Control',
    severity: 'Medium',
    description: 'Ensures that Microsoft Azure Virtual Network has flow logs enabled and configured to send logs to a Log Analytics workspace.',
    more_info: 'Enabling flow logs for Microsoft Azure Virtual Networks is essential for comprehensive network visibility, security enhancement, and optimizing resources by providing detailed insights into traffic patterns and potential threats. Sending logs to a Log Analytics workspace enables centralized analysis, correlation, and alerting for faster threat detection and response.',
    recommended_action: 'Enable flow logs for each Virtual Network and configure Traffic Analytics with a Log Analytics workspace.',
    link: 'https://learn.microsoft.com/en-us/azure/network-watcher/vnet-flow-logs-overview',
    apis: ['virtualNetworks:listAll', 'networkWatchers:listAll', 'flowLogs:list'],
    realtime_triggers: ['microsoftnetwork:virtualnetworks:write', 'microsoftnetwork:virtualnetworks:delete', 'microsoftnetwork:networkwatchers:flowlogs:write', 'microsoftnetwork:networkwatchers:flowlogs:delete'],

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

            const networkWatchers = helpers.addSource(cache, source,
                ['networkWatchers', 'listAll', location]);

            const vnetFlowLogs = [];
            if (networkWatchers && networkWatchers.data) {
                for (const networkWatcher of networkWatchers.data) {
                    const flowLogs = helpers.addSource(cache, source,
                        ['flowLogs', 'list', location, networkWatcher.id]);

                    if (!flowLogs || flowLogs.err || !flowLogs.data) {
                        helpers.addResult(results, 3,
                            'Unable to query for flow logs data: ' + helpers.addError(flowLogs), location);
                        return rcb();
                    }

                    flowLogs.data.forEach(fl => {
                        if (fl.targetResourceId &&
                            fl.targetResourceId.toLowerCase().includes('/virtualnetworks/')) {
                            vnetFlowLogs.push(fl);
                        }
                    });
                }
            }

            for (const virtualNetwork of virtualNetworks.data) {
                if (!virtualNetwork.id) continue;

                const flowLog = vnetFlowLogs.find(fl =>
                    fl.targetResourceId &&
                    fl.targetResourceId.toLowerCase() === virtualNetwork.id.toLowerCase()
                );

                if (!flowLog || !flowLog.enabled) {
                    helpers.addResult(results, 2,
                        'Virtual Network does not have flow logs enabled', location, virtualNetwork.id);
                    continue;
                }

                const analyticsConfig = flowLog.flowAnalyticsConfiguration &&
                    flowLog.flowAnalyticsConfiguration.networkWatcherFlowAnalyticsConfiguration;

                if (!analyticsConfig || !analyticsConfig.enabled || !analyticsConfig.workspaceId) {
                    helpers.addResult(results, 2,
                        'Virtual Network flow logs are not configured to send logs to Log Analytics',
                        location, virtualNetwork.id);
                } else {
                    helpers.addResult(results, 0,
                        'Virtual Network has flow logs enabled and configured to send to Log Analytics',
                        location, virtualNetwork.id);
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
