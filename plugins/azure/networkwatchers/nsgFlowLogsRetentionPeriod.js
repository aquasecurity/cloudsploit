const async = require('async');
const helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'NSG Flow Logs Retention Period',
    category: 'Network Watcher',
    domain: 'Management and Governance',
    description: 'Ensures that Azure Network Security Groups (NSGs) have a sufficient flow log retention period',
    more_info: 'A flow log data retention period of 90 days or more, allows you to collect the necessary amount of logging data required to check for anomalies and provide details about any potential security breach.',
    recommended_action: 'Modify NSG flow logs and set desired value in days for retention period',
    link: 'https://docs.microsoft.com/en-us/azure/network-watcher/network-watcher-nsg-flow-logging-portal',
    apis: ['networkWatchers:listAll', 'flowLogs:list'],
    settings: {
        nsg_flowlog_retention_period: {
            name: 'NSG Flow Log Retention Period',
            default: '90',
            description: 'Desired number of days for which NSG flow logs data will be retained.',
            regex: '^([1-9]|[1-9][0-9]|1[0-9][0-9]|2[0-9][0-9]|3[0-5][0-9]|36[0-5])$'
        }
    },

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        const config = {
            retentionDays: parseInt(settings.nsg_flowlog_retention_period || this.settings.nsg_flowlog_retention_period.default)
        };

        async.each(locations.networkWatchers, function(location, rcb) {
            const networkWatchers = helpers.addSource(cache, source,
                ['networkWatchers', 'listAll', location]);

            if (!networkWatchers) return rcb();

            if (networkWatchers.err || !networkWatchers.data) {
                helpers.addResult(results, 3,
                    'Unable to query for Network Watchers: ' + helpers.addError(networkWatchers), location);
                return rcb();
            }

            if (!networkWatchers.data.length) {
                helpers.addResult(results, 0, 'No Network Watchers found', location);
                return rcb();
            }

            async.each(networkWatchers.data, function(networkWatcher, scb) {
                const flowLogs = helpers.addSource(cache, source,
                    ['flowLogs', 'list', location, networkWatcher.id]);

                if (!flowLogs || flowLogs.err || !flowLogs.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for flow logs data: ' + helpers.addError(networkWatchers), location);
                    return scb();
                }

                if (!flowLogs.data.length) {
                    helpers.addResult(results, 0, 'No flow logs data found', location);
                    return scb();
                }

                for (const flowLog of flowLogs.data) {
                    if (!flowLog.id) continue;
                    let retentionDays = 0;
                    if (flowLog.retentionPolicy && flowLog.retentionPolicy.days) {
                        retentionDays = flowLog.retentionPolicy.days;
                    }

                    if (retentionDays >= config.retentionDays) {
                        helpers.addResult(results, 0,
                            `NSG fLow log has retention period set to ${retentionDays} of ${config.retentionDays} days desired limit`,
                            location, flowLog.id);
                    } else {
                        helpers.addResult(results, 2,
                            `NSG fLow log has retention period set to ${retentionDays} of ${config.retentionDays} days desired limit`,
                            location, flowLog.id);
                    }
                }

                scb();
            }, function() {
                rcb();
            });
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
