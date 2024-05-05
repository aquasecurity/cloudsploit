const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'PostgreSQL FLexible Server Log Duration Enabled',
    category: 'PostgreSQL Server',
    domain: 'Databases',
    severity: 'Low',
    description: 'Ensures connection duration logs are enabled for PostgreSQL flexible servers.',
    more_info: 'Enabling connection duration logs on PostgreSQL flexible servers allows for logging the duration of each completed SQL statement, aiding in performance monitoring, identifying long-running queries, and ensuring compliance with auditing requirements.',
    recommended_action: 'Ensure the server parameters for each PostgreSQL flexible servers have the log_duration setting enabled.',
    link: 'https://learn.microsoft.com/en-us/azure/flexible-server/howto-configure-server-parameters-using-portal',
    apis: ['servers:listPostgresFlexibleServer', 'flexibleServersConfigurations:listByPostgresServer'], 
    realtime_triggers: ['microsoftdbforpostgresql:flexibleservers:write','microsoftdbforpostgresql:flexibleservers:delete','microsoftdbforpostgresql:flexibleservers:configurations:write'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.servers, (location, rcb) => {
            const servers = helpers.addSource(cache, source,
                ['servers', 'listPostgresFlexibleServer', location]);

            helpers.checkFlexibleServerConfigs(servers, cache, source, location, results, 'PostgreSQL Flexible', 'log_duration', 'Duration logs');
            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
