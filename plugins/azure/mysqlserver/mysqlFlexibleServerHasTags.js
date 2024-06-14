const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'MySQL Flexible Server Has Tags',
    category: 'MySQL Server',
    domain: 'Databases',
    severity: 'Low',
    description: 'Ensure that Azure MySQL Flexible servers have tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    recommended_action: 'Modify MySQL Flexible server and add tags.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/tag-resources',
    apis: ['servers:listMysql', 'servers:listMysqlFlexibleServer'],
    realtime_triggers: ['microsoftdbformysql:flexibleservers:write','microsoftdbformysql:flexibleservers:delete'],


    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.servers, (location, rcb) => {

            const servers = helpers.addSource(cache, source,
                ['servers', 'listMysqlFlexibleServer', location]);

            if (!servers) return rcb();
                
            if (servers.err || !servers.data) {
                helpers.addResult(results, 3,
                    'Unable to query for MySQL flexible servers: ' + helpers.addError(servers), location);
                return rcb();
            }

            if (!servers.data.length) {
                helpers.addResult(results, 0, 'No existing MySQL flexible servers found', location);
                return rcb();
            }

            for (var flexibleServer of servers.data) {
                if (!flexibleServer.id) continue;
                
                if (flexibleServer.tags && Object.entries(flexibleServer.tags).length > 0){
                    helpers.addResult(results, 0, 'MySQL Flexible server has tags associated', location, flexibleServer.id);
                } else {
                    helpers.addResult(results, 2, 'MySQL Flexible server does not have tags associated', location, flexibleServer.id);
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    },
};