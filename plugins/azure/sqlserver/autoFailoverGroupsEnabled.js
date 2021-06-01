var async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Auto-Failover Groups Enabled',
    category: 'SQL Server',
    description: 'Ensures that auto-failover groups are configured for Azure SQL database servers.',
    more_info: 'In case of any outage that impacts one or more SQL databases, automatic failover process switches all secondary databases in the group to primary databases to ensure high availability.',
    recommended_action: 'Ensure that auto-failover Groups are configured for Azure SQL database servers',
    link: 'https://docs.microsoft.com/en-us/azure/azure-sql/database/auto-failover-group-overview',
    apis: ['servers:listSql', 'failoverGroups:listByServer'],

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

            for (const server of servers.data) {
                const failoverGroups = helpers.addSource(cache, source,
                    ['failoverGroups', 'listByServer', location, server.id]);

                if (!failoverGroups || failoverGroups.err || !failoverGroups.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for auto-failover groups: ' + helpers.addError(failoverGroups), location, server.id);
                    continue;
                }

                if (failoverGroups.data.length) {
                    helpers.addResult(results, 0, 'Auto-failover groups are configured for the SQL server', location, server.id);
                } else {
                    helpers.addResult(results, 2, 'Auto-failover groups are not configured for the SQL server', location, server.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
