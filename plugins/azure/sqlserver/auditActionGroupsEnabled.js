var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Audit Action Groups Enabled',
    category: 'SQL Server',
    description: 'Ensures that SQL Server Audit Action and Groups is configured properly',
    more_info: 'SQL Server Audit Action and Groups should be configured to at least include SUCCESSFUL_DATABASE_AUTHENTICATION_GROUP, FAILED_DATABASE_AUTHENTICATION_GROUP and BATCH_COMPLETED_GROUP.',
    recommended_action: 'If SQL Server Audit Action and Groups is not configured properly when enabling Auditing, these settings must be configured in Powershell.',
    link: 'https://docs.microsoft.com/en-us/azure/sql-database/sql-database-auditing',
    apis: ['servers:listSql', 'serverBlobAuditingPolicies:get'],
    compliance: {
        hipaa: 'HIPAA requires that a secure audit record for ' +
            'write read and delete is created for all ' +
            'activities in the system.'
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.servers, function(location, rcb) {

            var servers = helpers.addSource(cache, source,
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
                    // TODO: should this be a FAIL?
                    if (!serverBlobAuditingPolicies.data.length) {
                        helpers.addResult(results, 0, 'No Server Auditing policies found', location, server.id);
                    } else {
                        serverBlobAuditingPolicies.data.forEach(serverBlobAuditingPolicy => {
                            if (serverBlobAuditingPolicy.auditActionsAndGroups &&
                                serverBlobAuditingPolicy.auditActionsAndGroups.length) {
                                if (serverBlobAuditingPolicy.auditActionsAndGroups.indexOf('SUCCESSFUL_DATABASE_AUTHENTICATION_GROUP') > -1 &&
                                    serverBlobAuditingPolicy.auditActionsAndGroups.indexOf('FAILED_DATABASE_AUTHENTICATION_GROUP') > -1 &&
                                    serverBlobAuditingPolicy.auditActionsAndGroups.indexOf('BATCH_COMPLETED_GROUP') > -1) {
                                    helpers.addResult(results, 0, 'Audit Action and Groups is enabled on the SQL Server', location, server.id);
                                } else {
                                    helpers.addResult(results, 2, 'Audit Action and Groups is not configured properly on the SQL Server', location, server.id);
                                }
                            } else {
                                helpers.addResult(results, 2, 'Audit Action and Groups is disabled on the SQL Server', location, server.id);
                            }
                        });
                    }
                }
            });

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
