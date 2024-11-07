var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Database Private Link Enabled',
    category: 'SQL Databases',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensures SQL Database sync groups are configured to use private link.',
    more_info: 'Private link feature allows you to choose a service managed private endpoint to establish a secure connection between the sync service and your member/hub databases during the data synchronization process. A service managed private endpoint is a private IP address within a specific virtual network and subnet.',
    recommended_action: 'Configure SQL Database sync groups to use private link and mandate manual approval for private endpoint connections.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-sql/database/sql-data-sync-data-sql-server-sql-database?view=azuresql',
    apis: ['servers:listSql', 'databases:listByServer', 'syncGroups:list'],
    realtime_triggers: ['microsoftsql:servers:write', 'microsoftsql:servers:delete', 'microsoftsql:servers:databases:write', 'microsoftsql:servers:databases:syncgroups:write', 'microsoftsql:servers:databases:delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.servers, function(location, rcb) {
            var servers = helpers.addSource(cache, source, ['servers', 'listSql', location]);

            if (!servers) return rcb();

            if (servers.err || !servers.data) {
                helpers.addResult(results, 3, 'Unable to query for SQL servers: ' + helpers.addError(servers), location);
                return rcb();
            }

            if (!servers.data.length) {
                helpers.addResult(results, 0, 'No SQL servers found', location);
                return rcb();
            }

            // Loop through servers and check databases
            servers.data.forEach(function(server) {

                var databases = helpers.addSource(cache, source,
                    ['databases', 'listByServer', location, server.id]);

                if (!databases || databases.err || !databases.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for SQL server databases: ' + helpers.addError(databases), location, server.id);
                } else {
                    if (!databases.data.length) {
                        helpers.addResult(results, 0,
                            'No databases found for SQL server', location, server.id);
                    } else {
                        databases.data.forEach(database => {

                            if (database.name && database.name.toLowerCase() !== 'master') {

                                var syncGroups = helpers.addSource(cache, source, ['syncGroups', 'list', location, database.id]);

                                if (!syncGroups || syncGroups.err || !syncGroups.data) {
                                    helpers.addResult(results, 3, 'Unable to query for SQL Database sync groups: ' + helpers.addError(syncGroups), location, database.id);
                                    return;
                                }
                                if (!syncGroups.data.length) {
                                    helpers.addResult(results, 0,
                                        'No sync groups found for SQL database', location, database.id);
                                } else {
                                    var missingPrivateConfigGrps = syncGroups.data.filter((e) => !e.usePrivateLinkConnection).map((e) => e.name);

                                    if (missingPrivateConfigGrps.length) {
                                        helpers.addResult(results, 2, `Following SQL Database sync groups are not configured to use private link: ${missingPrivateConfigGrps.join(', ')} `, location, database.id);

                                    } else {
                                        helpers.addResult(results, 0, 'All SQL Database sync groups are configured to use private link', location, database.id);
                                    }
                                }
                            }
                        });
                    }
                }

            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
