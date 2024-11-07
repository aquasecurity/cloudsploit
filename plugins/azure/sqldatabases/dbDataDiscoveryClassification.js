var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'SQL Database Data Discovery and Classification',
    category: 'SQL Databases',
    domain: 'Databases',
    severity: 'Low',
    description: 'Ensures that data discovery and classification is implemented for SQL databases',
    more_info: 'Enabling Data Discovery & Classification for Azure SQL Server databases helps identify, classify, and protect sensitive data, ensuring compliance with privacy standards and regulatory requirements. It enhances security by providing insights into data exposure risks.',
    recommended_action: 'Implement data discovery and appropriate classifications for SQL databases.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-sql/database/data-discovery-and-classification-overview?view=azuresql',
    apis: ['servers:listSql', 'databases:listByServer', 'currentSensitivityLabels:list'],
    realtime_triggers: ['microsoftsql:servers:write', 'microsoftsql:servers:delete', 'microsoftsql:servers:databases:write', 'microsoftsql:servers:databases:delete'],

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

            servers.data.forEach(server => {
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

                            if (database.name && database.name.toLowerCase() !== 'master') {
                                var currentSensitivityLabels = helpers.addSource(cache, source, ['currentSensitivityLabels', 'list', location, database.id]);

                                if (!currentSensitivityLabels || !currentSensitivityLabels.data ||  currentSensitivityLabels.err) {
                                    helpers.addResult(results, 2, 'Unable to query data discovery and classification information: ' + helpers.addError(currentSensitivityLabels), location, database.id);
                                } else {
                                    if (currentSensitivityLabels.data.length) {
                                        helpers.addResult(results, 0, 'SQL Database is using data discovery and classification', location, database.id);
                                    } else {
                                        helpers.addResult(results, 2, 'SQL Database is not using data discovery and classification', location, database.id);
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
