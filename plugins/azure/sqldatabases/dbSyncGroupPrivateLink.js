var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'SQL Database Sync Groups - Private Link & Manual Approval',
    category: 'SQL Databases',
    domain: 'Databases',
    description: 'Ensures SQL Database sync groups use private link when SQL DB sync with others databases.',
    more_info: 'Using private link for SQL Database sync groups adds an extra layer of security by requiring manual approval for private endpoint connections.',
    recommended_action: 'Configure SQL Database sync groups to use private link and mandate manual approval for private endpoint connections.',
    link: 'https://learn.microsoft.com/en-us/azure/private-link/private-link-overview',
    apis: ['servers:listSql','databases:listByServer','syncGroups:list'],
    
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
                        databases.data.forEach(function(database) {
                            
                            var syncGroups = helpers.addSource(cache, source, ['syncGroups', 'list', location, database.id]);

                            if (!syncGroups || syncGroups.err || !syncGroups.data) {
                                helpers.addResult(results, 3, 'Unable to query for SQL Database sync groups: ' + helpers.addError(syncGroups), location, database.id);
                                return;
                            }
                            if (!syncGroups.data.length) {
                                helpers.addResult(results, 0,
                                    'No Database sync group found for SQL database', location, database.id);
                            }

                            syncGroups.data.forEach(function(syncGroup) {
                                if (syncGroup.usePrivateLinkConnection) {
                                    helpers.addResult(results, 0, 'SQL Database sync group uses private link to sync with other databases', location, syncGroup.id);
                                } else {
                                    helpers.addResult(results, 2, 'SQL Database sync group does not uses private link to sync with other databases', location, syncGroup.id);
                                }
                            });
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
