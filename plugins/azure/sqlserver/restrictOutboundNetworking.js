var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Server Outbound Networking Restricted',
    category: 'SQL Server',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensure outbound networking restrictions are configured for the Azure SQL logical server.',
    more_info: 'Outbound firewall rules limit network traffic from the Azure SQL logical server to a customer-defined list of Azure Storage accounts and Azure SQL logical servers. Any attempt to access storage accounts or databases not in this list is denied.',
    recommended_action: 'Configure outbound networking restrictions to allow access only to specified Azure Storage accounts and Azure SQL logical servers.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-sql/database/outbound-firewall-rule-overview?view=azuresql',
    apis: ['servers:listSql'],
    realtime_triggers: ['microsoftsql:servers:write', 'microsoftsql:servers:delete'],

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

            servers.data.forEach(server=> {
                if (server.restrictOutboundNetworkAccess && server.restrictOutboundNetworkAccess.toLowerCase() == 'enabled') {
                    helpers.addResult(results, 0, 'Outbound networking restrictions are configured for SQL server', location, server.id);
                } else {
                    helpers.addResult(results, 2, 'Outbound networking restrictions are not configured for SQL server', location, server.id);
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
