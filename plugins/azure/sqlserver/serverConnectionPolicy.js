const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'SQL Server Connection Policy',
    category: 'SQL Server',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensures that the connection policy is set to "Redirect" for SQL server.',
    more_info: 'Redirect policy means that after the TCP session is established to Azure SQL Database, the client session is then redirected to the right database cluster with a change to the destination virtual IP from that of the Azure SQL Database gateway to that of the cluster. This establishes connections directly to the node hosting the database, leading to reduced latency and improved throughput.',
    recommended_action: 'Ensure that connection policy is set to "Redirect" for each SQL server.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-sql/database/connectivity-architecture?view=azuresql',
    apis: ['servers:listSql', 'connectionPolicies:listByServer'],
    realtime_triggers: ['microsoftsql:servers:write', 'microsoftsql:servers:delete','microsoftsql:servers:connectionpolicies:write'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

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
                const connectionPolicies = helpers.addSource(cache, source,
                    ['connectionPolicies', 'listByServer', location, server.id]);

                if (!connectionPolicies || connectionPolicies.err || !connectionPolicies.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for SQL Server connection policies: ' + helpers.addError(connectionPolicies), location, server.id);
                } else {
                    if (connectionPolicies.data.length) {
                        if (connectionPolicies.data[0].connectionType && connectionPolicies.data[0].connectionType.toLowerCase() == 'redirect') {
                            helpers.addResult(results, 0,
                                'Connection policy is set to "Redirect" for SQL server', location, server.id);
                        } else {
                            helpers.addResult(results, 2,
                                'Connection policy is not set to "Redirect" for SQL server', location, server.id);
                        }
                    } else {
                        helpers.addResult(results, 0,
                            'No Connection policies found', location, server.id);
                    }
                    
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
