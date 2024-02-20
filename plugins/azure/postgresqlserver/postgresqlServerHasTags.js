const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'PostgreSQL Server Has Tags',
    category: 'PostgreSQL Server',
    domain: 'Databases',
    severity: 'Low',
    description: 'Ensure that Azure PostgreSQL servers have tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    recommended_action: 'Modify PostgreSQL servers and add tags.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/tag-resources',
    apis: ['servers:listPostgres'],
    realtime_triggers: ['microsoftdbforpostgresql:servers:write','microsoftdbforpostgresql:servers:delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.servers, (location, rcb) => {

            const listPostgres = helpers.addSource(cache, source,
                ['servers', 'listPostgres', location]);

            if (!listPostgres) return rcb();

            if (listPostgres.err || !listPostgres.data) {
                helpers.addResult(results, 3,
                    'Unable to query for PostgreSQL Servers: ' + helpers.addError(listPostgres), location);
                return rcb();
            }

            if (!listPostgres.data.length) {
                helpers.addResult(results, 0, 'No existing PostgreSQL Servers found', location);
                return rcb();
            }
            for (let postgresServer of listPostgres.data) {
                if (!postgresServer.id) continue;

                if (postgresServer.tags && Object.entries(postgresServer.tags).length > 0){
                    helpers.addResult(results, 0, 'PostgreSQL Server has tags associated', location, postgresServer.id);
                } else {
                    helpers.addResult(results, 2, 'PostgreSQL Server does not have tags associated', location, postgresServer.id);
                } 
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
