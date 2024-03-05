const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'SQL Server Services Access Disabled',
    category: 'SQL Server',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensure that SQL servers do not allow access to other Azure services.',
    more_info: 'To secure your SQL server, it is recommended to disable public network access or access to all Azure services. Instead, configure firewall or VNET rules to allow connections from specific network ranges or from designated virtual networks. This helps prevent unauthorized access from Azure services outside your subscription.',
    recommended_action: 'Disable public access and remove "allowallwindowsazureips" firewall rule for all SQL Servers.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-sql/database/network-access-controls-overview?view=azuresql',
    apis: ['servers:listSql','firewallRules:listByServer'],
    realtime_triggers: ['microsoftsql:servers:write', 'microsoftsql:servers:delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.servers, (location, rcb) => {
            const servers = helpers.addSource(cache, source,
                ['servers', 'listSql', location]);

            if (!servers) return rcb();

            if (servers.err || !servers.data) {
                helpers.addResult(results, 3,
                    'Unable to query for SQL servers: ' + helpers.addError(servers), location);
                return rcb();
            }

            if (!servers.data.length) {
                helpers.addResult(results, 0, 'No existing SQL servers found', location);
                return rcb();
            }

            servers.data.forEach(function(server) {

                const firewallRules = helpers.addSource(cache, source,
                    ['firewallRules', 'listByServer', location, server.id]);

                if (!firewallRules || firewallRules.err || !firewallRules.data) {
                    helpers.addResult(results, 3,
                        'Unable to query SQL Server Firewall Rules: ' + helpers.addError(firewallRules), location, server.id);
                    return;
                    
                }

                if (!firewallRules.data.length) {
                    helpers.addResult(results, 0, 'No existing SQL Server Firewall Rules found', location, server.id);
                    return;
                    
                }

                let accessToServices = false;
                for (let rule of firewallRules.data) {
                    if (rule.name && rule.name.toLowerCase() === 'allowallwindowsazureips') {
                        accessToServices = true;
                        break;
                    }
                }

                if (!accessToServices || (server.publicNetworkAccess && server.publicNetworkAccess.toLowerCase() == 'disabled')) {
                    helpers.addResult(results, 0,
                        'Access to other Azure services is disabled for SQL server', location, server.id);
                } else {
                    helpers.addResult(results, 2,
                        'Access to other Azure services is not disabled for SQL server', location, server.id);
                }
            });

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
