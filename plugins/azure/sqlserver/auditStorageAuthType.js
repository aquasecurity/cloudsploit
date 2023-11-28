var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Storage Authentication Type for Audit Logs',
    category: 'SQL Server',
    domain: 'Databases',
    description: 'Ensure managed identity is set as the authentication type when storage account is chosen as the destination for audit logs on SQL server.',
    more_info: 'Enabling managed identity as authentication type enhances security when using a storage account as the destination for audit logs.',
    recommended_action: 'Configure managed identity as the authentication type when choosing a storage account as the destination for audit logs on SQL server.',
    link: 'https://docs.microsoft.com/en-us/azure/azure-sql/database/security-enhanced-auditing?tabs=azure-powershell#configure-azure-storage-account',
    apis: ['servers:listSql', 'serverBlobAuditingPolicies:get'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

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

            servers.data.forEach(function(server) {
                const serverBlobAuditingPolicies = helpers.addSource(cache, source,
                    ['serverBlobAuditingPolicies', 'get', location, server.id]);

                if (!serverBlobAuditingPolicies || serverBlobAuditingPolicies.err || !serverBlobAuditingPolicies.data) {
                    helpers.addResult(results, 3,
                        'Unable to query Auditing Policies: ' + helpers.addError(serverBlobAuditingPolicies), location, server.id);
                } else {
                    if (!serverBlobAuditingPolicies.data.length) {
                        helpers.addResult(results, 0, 'No Server Auditing policies found', location, server.id);
                    } else {
                        serverBlobAuditingPolicies.data.forEach(serverBlobAuditingPolicy => {
                            if (serverBlobAuditingPolicy.state.toLowerCase()=='enabled') {
                                if (serverBlobAuditingPolicy.storageAccountSubscriptionId !== '00000000-0000-0000-0000-000000000000') {
                                    if (serverBlobAuditingPolicy.isManagedIdentityInUse) {
                                        helpers.addResult(results, 0, 'Managed identity is configured as authentication type for audit logs storage on the SQL server', location, server.id);
                                    } else {
                                        helpers.addResult(results, 2, 'Managed identity is not configured as authentication type for audit logs storage on the SQL server', location, server.id);
                                    }
                                } else {
                                    helpers.addResult(results, 0, 'Azure SQL Auditing not using account storage for the SQL serverr', location, server.id);
                                }
                            } else {
                                helpers.addResult(results, 0, 'Azure SQL Auditing disabled for the SQL server', location, server.id);
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
