var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Server Auditing Enabled',
    category: 'SQL Server',
    description: 'Ensures that SQL Server Auditing is enabled for SQL servers',
    more_info: 'Enabling SQL Server Auditing ensures that all activities are being logged properly, including potentially-malicious activity.',
    recommended_action: 'Ensure that auditing is enabled for each SQL server.',
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
                    if (!serverBlobAuditingPolicies.data.length) {
                        helpers.addResult(results, 2, 'No Server Auditing policies found', location, server.id);
                    } else {
                        serverBlobAuditingPolicies.data.forEach(serverBlobAuditingPolicy => {
                            if (serverBlobAuditingPolicy.state &&
                                serverBlobAuditingPolicy.state.toLowerCase() === 'enabled') {
                                helpers.addResult(results, 0, 'Server auditing is enabled on the SQL Server', location, server.id);
                            } else {
                                helpers.addResult(results, 2, 'Server auditing is not enabled on the SQL Server', location, server.id);
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
