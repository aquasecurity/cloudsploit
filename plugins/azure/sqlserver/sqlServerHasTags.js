const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'SQL Server Has Tags',
    category: 'SQL Server',
    domain: 'Databases',
    severity: 'Low',
    description: 'Ensure that Azure SQL servers have tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    recommended_action: 'Modify SQL Server and add tags.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/tag-resources',
    apis: ['servers:listSql'],
    realtime_triggers: ['microsoftsql:servers:write', 'microsoftsql:servers:delete','microsoftresources:tags:write'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

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

            for (let server of servers.data) {
                if (!server.id) continue;
                
                if (server.tags && Object.entries(server.tags).length > 0){
                    helpers.addResult(results, 0, 'SQL Server has tags', location, server.id);
                } else {
                    helpers.addResult(results, 2, 'SQL Server does not have tags', location, server.id);
                }
            }
          
            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
