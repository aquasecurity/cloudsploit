var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Data Discovery and Classification for SQL Databases',
    category: 'SQL Databases',
    domain: 'Databases',
    description: 'Ensures that data discovery and classification is implemented for SQL databases.',
    more_info: 'Data Discovery & Classification is built into Azure SQL Database, Azure SQL Managed Instance, and Azure Synapse Analytics. It provides basic capabilities for discovering, classifying, labeling, and reporting the sensitive data in your databases.',
    recommended_action: 'Implement data discovery and classification for SQL databases.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-sql/database/data-discovery-and-classification-overview?view=azuresql',
    apis: ['servers:listSql', 'databases:listByServer', 'currentSensitivityLabels:list'],
    
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

                            var currentSensitivityLabels = helpers.addSource(cache, source, ['currentSensitivityLabels', 'list', location, database.id]);

                            if (!currentSensitivityLabels || !currentSensitivityLabels.data ||  currentSensitivityLabels.err) {
                                helpers.addResult(results, 2, 'Unable to query data discovery and classification information: ' + helpers.addError(currentSensitivityLabels), location, database.id);
                            } else {
                                if (currentSensitivityLabels.data.length) {
                                    helpers.addResult(results, 0, 'Data discovery and classification is being used', location, database.id);
                                } else {
                                    helpers.addResult(results, 2, 'SQL Database is not using data discovery and classification', location, database.id);
                                }
                            }
                        } );
                        
                    }
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
