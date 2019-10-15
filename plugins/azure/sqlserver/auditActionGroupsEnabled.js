var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Audit Action Groups Enabled',
    category: 'SQL Server',
    description: 'Ensures that SQL Server Audit Action and Groups is configured properly',
    more_info: 'SQL Server Audit Action and Groups should be configured to at least include SUCCESSFUL_DATABASE_AUTHENTICATION_GROUP, FAILED_DATABASE_AUTHENTICATION_GROUP and BATCH_COMPLETED_GROUP.',
    recommended_action: 'If SQL Server Audit Action and Groups is not configured properly when enabling Auditing, these settings must be configured in Powershell.',
    link: 'https://docs.microsoft.com/en-us/azure/sql-database/sql-database-auditing',
    apis: ['servers:sql:list', 'serverBlobAuditingPolicies:get'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.databases, function(location, rcb){
            var serverBlobAuditingPolicies = helpers.addSource(cache, source,
                ['serverBlobAuditingPolicies', 'get', location]);

            if (!serverBlobAuditingPolicies) return rcb();

            if (serverBlobAuditingPolicies.err || !serverBlobAuditingPolicies.data) {
                helpers.addResult(results, 3,
                    'Unable to query Auditing Policies: ' + helpers.addError(serverBlobAuditingPolicies), location);
                return rcb();
            }

            if (!serverBlobAuditingPolicies.data.length) {
                helpers.addResult(results, 0, 'No Server Auditing policies found', location);
                return rcb();
            }

            serverBlobAuditingPolicies.data.forEach(serverBlobAuditingPolicy => {
                var serverIdArr = serverBlobAuditingPolicy.id.split('/');
                serverIdArr.length = serverIdArr.length - 2;
                var serverId = serverIdArr.join('/');

                if (serverBlobAuditingPolicy.auditActionsAndGroups &&
                    serverBlobAuditingPolicy.auditActionsAndGroups.length) {
                    if (serverBlobAuditingPolicy.auditActionsAndGroups.indexOf("SUCCESSFUL_DATABASE_AUTHENTICATION_GROUP") > -1 &&
                        serverBlobAuditingPolicy.auditActionsAndGroups.indexOf("FAILED_DATABASE_AUTHENTICATION_GROUP") > -1 &&
                        serverBlobAuditingPolicy.auditActionsAndGroups.indexOf("BATCH_COMPLETED_GROUP") > -1) {
                        helpers.addResult(results, 0, 'Audit Action and Groups is enabled on the SQL Server', location, serverId);
                    } else {
                        helpers.addResult(results, 2, 'Audit Action and Groups is not configured properly on the SQL Server', location, serverId);
                    }
                } else {
                    helpers.addResult(results, 2, 'Audit Action and Groups is disabled on the SQL Server', location, serverId);
                }
            });

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
