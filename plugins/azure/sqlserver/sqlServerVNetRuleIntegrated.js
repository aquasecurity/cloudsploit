const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'SQL Server VNet Rules Integrated',
    category: 'SQL Server',
    domain: 'Databases',
    severity: 'Medium',

    description: 'Ensures that SQL servers have VNet rules integrated.',
    more_info: 'Configuring SQL server to operate within a Virtual Network (VNet) offers a myriad of benefits for enhanced security and operational control. Integrating with a VNet enables proactive safeguarding of your server against potential security threats and unauthorized access.',
    recommended_action: 'Ensure VNet rule is integrated for all SQL servers.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-sql/database/vnet-service-endpoint-rule-overview?view=azuresql',
    apis: ['servers:listSql','virtualNetworkRules:listByServer'],
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

                const virtualNetworkRules = helpers.addSource(cache, source,
                    ['virtualNetworkRules', 'listByServer', location, server.id]);

                if (!virtualNetworkRules || virtualNetworkRules.err || !virtualNetworkRules.data) {
                    helpers.addResult(results, 3,
                        'Unable to query SQL Server VNet Rules: ' + helpers.addError(virtualNetworkRules), location, server.id);
                    return;
                    
                }

                if (virtualNetworkRules.data.length) {
                    helpers.addResult(results, 0, 'SQL server has VNet rule integrated', location, server.id);
                } else {
                    helpers.addResult(results, 2, 'SQL server does not have VNet rule integrated',location, server.id);
                }
            });

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
