const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'TDE Protector Encrypted',
    category: 'SQL Server',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensures SQL Server TDE protector is encrypted with BYOK (Bring Your Own Key)',
    more_info: 'Enabling BYOK in the TDE protector allows for greater control and transparency, as well as increasing security by having full control of the encryption keys.',
    recommended_action: 'Ensure that a BYOK key is set for the Transparent Data Encryption of each SQL Server or Managed Instance.',
    link: 'https://learn.microsoft.com/en-us/azure/sql-database/transparent-data-encryption-byok-azure-sql',
    apis: ['servers:listSql', 'encryptionProtectors:listByServer', 'managedInstances:list', 'managedInstanceEncryptionProtectors:listByInstance'], 
    settings: {
        sql_tde_protector_encryption_key: {
            name: 'SQL Server TDE Protector Encryption Key Type',
            description: 'Desired encryption key for SQL Server and Managed Instance transparent data encryption; default=service-managed key, cmk=customer-managed key',
            regex: '(default|byok)',
            default: 'byok'
        }
    },
    
    realtime_triggers: ['microsoftsql:servers:write', 'microsoftsql:servers:delete', 'microsoftsql:servers:encryptionprotector:write'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);
    
        var config = {
            sql_tde_protector_encryption_key: settings.sql_tde_protector_encryption_key || this.settings.sql_tde_protector_encryption_key.default
        };
    
        function checkEncryptionProtection(encryptionProtector, location, config) {
            if (config.sql_tde_protector_encryption_key == 'byok') {
                if ((encryptionProtector.kind &&
                    encryptionProtector.kind.toLowerCase() != 'azurekeyvault') ||
                    (encryptionProtector.serverKeyType &&
                        encryptionProtector.serverKeyType.toLowerCase() != 'azurekeyvault') ||
                    !encryptionProtector.uri) {
                    helpers.addResult(results, 2,
                        'SQL Server TDE protector is not encrypted with BYOK', location, encryptionProtector.id);
                } else {
                    helpers.addResult(results, 0,
                        'SQL Server TDE protector is encrypted with BYOK', location, encryptionProtector.id);
                }
            } else {
                helpers.addResult(results, 0,
                    'SQL Server TDE protector is encrypted with service-managed key', location, encryptionProtector.id);
            }
        }
    
        async.each(locations.servers, function(location, rcb) {
            async.parallel([
                // Check SQL Servers
                function(cb) {
                    const servers = helpers.addSource(cache, source,
                        ['servers', 'listSql', location]);
    
                    if (!servers) return cb();
    
                    if (servers.err || !servers.data) {
                        helpers.addResult(results, 3,
                            'Unable to query for SQL servers: ' + helpers.addError(servers), location);
                        return cb();
                    }
    
                    if (!servers.data.length) {
                        helpers.addResult(results, 0, 'No SQL servers found', location);
                        return cb();
                    }
    
                    servers.data.forEach(server => {
                        const encryptionProtectors = helpers.addSource(cache, source,
                            ['encryptionProtectors', 'listByServer', location, server.id]);
    
                        if (!encryptionProtectors || encryptionProtectors.err || !encryptionProtectors.data) {
                            helpers.addResult(results, 3,
                                'Unable to query for SQL Server Encryption Protectors: ' + helpers.addError(encryptionProtectors), location, server.id);
                        } else if (!encryptionProtectors.data.length) {
                            helpers.addResult(results, 0, 'No SQL Server Encryption Protectors found', location, server.id);
                        } else {
                            encryptionProtectors.data.forEach(protector => {
                                checkEncryptionProtection(protector, location, config);
                            });
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
                        const managedInstanceEncryptionProtectors = helpers.addSource(cache, source,
                            ['managedInstanceEncryptionProtectors', 'listByInstance', location, instance.id]);
    
                        if (!managedInstanceEncryptionProtectors || managedInstanceEncryptionProtectors.err || !managedInstanceEncryptionProtectors.data) {
                            helpers.addResult(results, 3,
                                'Unable to query for Managed Instance Encryption Protectors: ' + helpers.addError(managedInstanceEncryptionProtectors), location, instance.id);
                        } else if (!managedInstanceEncryptionProtectors.data.length) {
                            helpers.addResult(results, 0, 'No Managed Instance Encryption Protectors found', location, instance.id);
                        } else {
                            managedInstanceEncryptionProtectors.data.forEach(protector => {
                                checkEncryptionProtection(protector, location, config);
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
