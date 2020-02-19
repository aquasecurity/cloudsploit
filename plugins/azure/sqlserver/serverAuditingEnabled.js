var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Server Auditing Enabled',
    category: 'SQL Server',
    description: 'Ensures that SQL Server Auditing is enabled for SQL servers',
    more_info: 'Enabling SQL Server Auditing ensures that all activities are being logged properly, including potentially-malicious activity.',
    recommended_action: 'Ensure that auditing is enabled for each SQL server.',
    link: 'https://docs.microsoft.com/en-us/azure/sql-database/sql-database-auditing',
    apis: ['servers:sql:list', 'serverBlobAuditingPolicies:get'],
    compliance: {
        hipaa: 'HIPAA requires that a secure audit record for ' +
            'write read and delete is created for all ' +
            'activities in the system.'
    },

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

                if (serverBlobAuditingPolicy.state &&
                    serverBlobAuditingPolicy.state === 'Enabled') {
                    helpers.addResult(results, 0, 'Server auditing is enabled on the SQL Server', location, serverId);
                } else {
                    helpers.addResult(results, 2, 'Server auditing is not enabled on the SQL Server', location, serverId);
                }
            });

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
