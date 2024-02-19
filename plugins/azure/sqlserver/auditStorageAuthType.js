var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Auditing Storage Authentication Type',
    category: 'SQL Server',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensures that managed identity is configured as authentication type for SQL Server storage account audit logs.',
    more_info: 'Enabling managed identity as authentication type enhances security when using a storage account as the destination for audit logs. Managed Identity can be a system-assigned managed identity or user-assigned managed identity.',
    recommended_action: 'Ensure managed identity is configured as authentication type when choosing a storage account as the destination for audit logs on SQL server.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-sql/database/auditing-managed-identity?view=azuresql&tabs=azure-portal',
    apis: ['servers:listSql', 'serverBlobAuditingPolicies:get'],
    realtime_triggers: ['microsoftsql:servers:write', 'microsoftsql:servers:delete', 'microsoftsql:servers:auditingsettings:write'],

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

            servers.data.forEach(server => {
                const serverBlobAuditingPolicies = helpers.addSource(cache, source,
                    ['serverBlobAuditingPolicies', 'get', location, server.id]);

                if (!serverBlobAuditingPolicies || serverBlobAuditingPolicies.err || !serverBlobAuditingPolicies.data) {
                    helpers.addResult(results, 3,
                        'Unable to query Auditing Policies: ' + helpers.addError(serverBlobAuditingPolicies), location, server.id);
                } else {
                    if (!serverBlobAuditingPolicies.data.length) {
                        helpers.addResult(results, 0, 'No Server Auditing policies found', location, server.id);
                    } else {
                        let serverAuditingEnabled = serverBlobAuditingPolicies.data.length && serverBlobAuditingPolicies.data.find(auditPolicy => auditPolicy.state && auditPolicy.state.toLowerCase() == 'enabled');
                        if (serverAuditingEnabled) {
                            if (serverAuditingEnabled.storageAccountSubscriptionId !== '00000000-0000-0000-0000-000000000000') {
                                if (serverAuditingEnabled.isManagedIdentityInUse) {
                                    helpers.addResult(results, 0, 'SQL Server is using managed identity authentication for storage account audit logs', location, server.id);
                                } else {
                                    helpers.addResult(results, 2, 'SQL Server is not using managed identity authentication for storage account audit logs', location, server.id);
                                }
                            } else {
                                helpers.addResult(results, 0, 'SQL Server is not using a storage account as destination for audit logs', location, server.id);
                            }
                        } else {
                            helpers.addResult(results, 0, 'Auditing is not enabled for SQL server', location, server.id);
                        }
                    }
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
