var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Audit Retention Policy',
    category: 'SQL Server',
    description: 'Ensures that SQL Server Auditing retention policy is set to greater than 90 days',
    more_info: 'Enabling SQL Server Auditing ensures that all activities are being logged properly, including potentially-malicious activity. Having a long retention policy ensures that all logs are kept for auditing and legal purposes.',
    recommended_action: 'Ensure that the storage account retention policy for each SQL server is set to greater than 90 days.',
    link: 'https://docs.microsoft.com/en-us/azure/sql-database/sql-database-auditing',
    apis: ['servers:listSql', 'serverBlobAuditingPolicies:get'],

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
                            if (serverBlobAuditingPolicy.retentionDays &&
                                serverBlobAuditingPolicy.retentionDays > 90) {
                                helpers.addResult(results, 0, 'Server Auditing retention is greater than 90 days', location, server.id);
                            } else if (serverBlobAuditingPolicy.retentionDays &&
                                serverBlobAuditingPolicy.retentionDays < 90) {
                                helpers.addResult(results, 2, `Server Auditing retention is ${serverBlobAuditingPolicy.retentionDays} days`, location, server.id);
                            } else {
                                helpers.addResult(results, 2, 'Server Auditing is not being stored in a storage account', location, server.id);
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