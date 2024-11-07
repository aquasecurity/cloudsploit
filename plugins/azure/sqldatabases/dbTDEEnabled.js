var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Transparent Data Encryption Enabled',
    category: 'SQL Databases',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensure that Transparent Data Encryption (TDE) is enabled for SQL databases.',
    more_info: 'Transparent data encryption (TDE) helps protect Azure SQL Databases, Managed Instances, and Synapse Analytics against the threat of malicious offline activity by encrypting data at rest. It performs real-time encryption and decryption of the database, associated backups, and transaction log files at rest without requiring changes to the application.',
    recommended_action: 'Modify SQL database and enable Transparent Data Encryption (TDE).',
    link: 'https://docs.microsoft.com/en-us/sql/relational-databases/security/encryption/transparent-data-encryption?view=sql-server-ver15',
    apis: ['servers:listSql', 'databases:listByServer', 'transparentDataEncryption:list', 'managedInstances:list', 'managedDatabases:listByInstance'],
    realtime_triggers: ['microsoftsql:servers:write', 'microsoftsql:servers:delete', 'microsoftsql:servers:databases:write', 'microsoftsql:servers:databases:transparentdataencryption:write', 'microsoftsql:servers:databases:delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.servers, function(location, rcb) {
            async.parallel([
                // Check SQL Server Databases
                function(cb) {
                    const servers = helpers.addSource(cache, source, ['servers', 'listSql', location]);

                    if (!servers) return cb();

                    if (servers.err || !servers.data) {
                        helpers.addResult(results, 3, 'Unable to query for SQL servers: ' + helpers.addError(servers), location);
                        return cb();
                    }

                    if (!servers.data.length) {
                        helpers.addResult(results, 0, 'No SQL servers found', location);
                        return cb();
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
                                databases.data.forEach(database => {

                                    if (database.name && database.name.toLowerCase() !== 'master') {
                                        var transparentDataEncryption = helpers.addSource(cache, source, 
                                        ['transparentDataEncryption', 'list', location, database.id]);

                                        if (!transparentDataEncryption || transparentDataEncryption.err ||
                                                 !transparentDataEncryption.data || !transparentDataEncryption.data.length) {
                                            helpers.addResult(results, 3, 'Unable to query transparent data encryption for SQL Database: ' + helpers.addError(transparentDataEncryption), location, database.id);
                                            return;
                                        }
                                        var encryption = transparentDataEncryption.data[0];
                                        if (encryption.state && encryption.state.toLowerCase() == 'enabled') {
                                            helpers.addResult(results, 0, 
                                                'SQL Database: Transparent data encryption is enabled', location, database.id);
                                        } else {
                                            helpers.addResult(results, 2, 
                                                'SQL Database: Transparent data encryption is not enabled', location, database.id);
                                        }
                                    }
                                });
                            }
                        }

                    });

                    cb();
                },
                // Check Managed Instances
                function(cb) {
                    const managedInstances = helpers.addSource(cache, source,
                        ['managedInstances', 'list', location]);

                    if (!managedInstances) return cb();

                    if (managedInstances.err || !managedInstances.data) {
                        helpers.addResult(results, 3,
                            'Unable to query for managed instances: ' + helpers.addError(managedInstances), location);
                        return cb();
                    }

                    if (!managedInstances.data.length) {
                        helpers.addResult(results, 0, 'No managed instances found', location);
                        return cb();
                    }

                    managedInstances.data.forEach(instance => {
                        const managedDatabases = helpers.addSource(cache, source,
                            ['managedDatabases', 'listByInstance', location, instance.id]);

                        if (!managedDatabases || managedDatabases.err || !managedDatabases.data) {
                            helpers.addResult(results, 3,
                                'Unable to query for managed instance databases: ' + helpers.addError(managedDatabases), location, instance.id);
                        } else if (!managedDatabases.data.length) {
                            helpers.addResult(results, 0,
                                'No databases found for managed instance', location, instance.id);
                        } else {
                            managedDatabases.data.forEach(database => {
                                if (database.name && database.name.toLowerCase() !== 'master') {
                                    // Managed instances have TDE enabled by default and cannot be disabled
                                    helpers.addResult(results, 0,
                                        'Managed Instance Database: Transparent data encryption is enabled', location, database.id);
                                }
                            });
                        }
                    });

                    cb();
                }
            ], function() {
                rcb();
            });
        }, function() {
            callback(null, results, source);
        });
    }
};
