var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Audit Retention Policy',
    category: 'SQL Server',
    description: 'Ensures that SQL Server Auditing retention policy is set to greater than 90 days',
    more_info: 'Enabling SQL Server Auditing ensures that all activities are being logged properly, including potentially-malicious activity. Having a long retention policy ensures that all logs are kept for auditing and legal purposes.',
    recommended_action: 'Ensure that the storage account retention policy for each SQL server is set to greater than 90 days.',
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
                    'Unable to query for Server Auditing policies: ' + helpers.addError(serverBlobAuditingPolicies), location);
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

                if (serverBlobAuditingPolicy.retentionDays &&
                    serverBlobAuditingPolicy.retentionDays > 90) {
                    helpers.addResult(results, 0, 'Server Auditing retention is greater than 90 days', location, serverId);
                } else if (!serverBlobAuditingPolicy.retentionDays ||
                            serverBlobAuditingPolicy.storageEndpoint === ''){
                    helpers.addResult(results, 2, 'Server Auditing is not being stored in a storage account', location, serverId);
                } else if (serverBlobAuditingPolicy.retentionDays &&
                            serverBlobAuditingPolicy.retentionDays < 90) {
                    helpers.addResult(results, 2, `Server Auditing retention is ${serverBlobAuditingPolicy.retentionDays} days`, location, serverId);
                }
            });

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};