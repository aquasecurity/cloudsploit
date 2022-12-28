const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'MySQL Server Has Tags',
    category: 'MySQL Server',
    domain: 'Databases',
    description: 'Ensure that Azure MySQL servers have tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    recommended_action: 'Modify MySQL server and add tags.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/tag-resources',
    apis: ['servers:listMysql'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.servers, (location, rcb) => {

            const servers = helpers.addSource(cache, source,
                ['servers', 'listMysql', location]);

            if (!servers) return rcb();

            if (servers.err || !servers.data) {
                helpers.addResult(results, 3,
                    'Unable to query for MySQL servers: ' + helpers.addError(servers), location);
                return rcb();
            }

            if (!servers.data.length) {
                helpers.addResult(results, 0, 'No existing MySQL servers found', location);
                return rcb();
            }

            for (let sqlserver of servers.data) {
                if (!sqlserver.id) continue;
                
                if (sqlserver.tags && Object.entries(sqlserver.tags).length > 0){
                    helpers.addResult(results, 0, 'MySQL server has tags associated', location, sqlserver.id);
                } else {
                    helpers.addResult(results, 2, 'MySQL server does not have tags associated', location, sqlserver.id);
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    },
};