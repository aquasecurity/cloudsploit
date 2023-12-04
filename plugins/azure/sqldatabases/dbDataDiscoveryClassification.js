var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Data Discovery and Classification for SQL Databases',
    category: 'SQL Databases',
    domain: 'Databases',
    description: 'Ensures that data discovery and classification is implemented for SQL databases.',
    more_info: 'Data discovery and classification help identify and label sensitive data, enabling better data protection and compliance.',
    recommended_action: 'Implement data discovery and classification for SQL databases to classify the sensitivity of your data. Add appropriate classifications as needed.',
    link: 'https://docs.microsoft.com/en-us/azure/sql-database/sql-database-data-discovery-and-classification-get-started-portal',
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
                                    helpers.addResult(results, 2, 'Data discovery and classification not being used.', location, database.id);
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
