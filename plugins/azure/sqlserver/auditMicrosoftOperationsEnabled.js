var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Microsoft Support Operations Auditing Enabled',
    category: 'SQL Server',
    domain: 'Databases',
    description: 'Ensure auditing of Microsoft support operations is enabled on SQL server.',
    more_info: 'Enabling this option captures Microsoft support engineers (DevOps) operations for enhanced monitoring and troubleshooting.',
    recommended_action: 'Enable the option to capture Microsoft support operations and write them to a selected Storage account, Log Analytics workspace, or Event Hub.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-sql/database/auditing-microsoft-support-operations?view=azuresql',
    apis: ['servers:listSql', 'devOpsAuditingSettings:list'],
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.servers, function(location, rcb) {

            const servers = helpers.addSource(cache, source,
                ['servers', 'listSql', location]);

            if (!servers) return rcb();

            if (servers.err || !servers.data) {
                helpers.addResult(results, 3,
                    'Unable to query for SQL servers: ' + helpers.addError(servers), location);
                return rcb();
            }

            if (!servers.data.length) {
                helpers.addResult(results, 0, 'No SQL servers found', location);
                return rcb();
            }

            servers.data.forEach(server => {
                const devOpsAuditingSettings = helpers.addSource(cache, source,
                    ['devOpsAuditingSettings', 'list', location, server.id]);

                if (!devOpsAuditingSettings || devOpsAuditingSettings.err || !devOpsAuditingSettings.data) {
                    helpers.addResult(results, 3,
                        'Unable to query Auditing Policies: ' + helpers.addError(devOpsAuditingSettings), location, server.id);
                } else {
                    if (devOpsAuditingSettings.data[0].state.toLowerCase() == 'enabled') {
                        helpers.addResult(results, 0, 'Microsoft support operations auditing is enabled on SQL server', location, server.id);
                    } else {
                        helpers.addResult(results, 2, 'Microsoft support operations auditing is not enabled on SQL server', location, server.id);
                    }
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
