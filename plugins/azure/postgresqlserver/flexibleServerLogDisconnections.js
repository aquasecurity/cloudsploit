const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'PostgreSQL FLexible Server Log Disconnections Enabled',
    category: 'PostgreSQL Server',
    domain: 'Databases',
    severity: 'Low',
    description: 'Ensures that disconnection logs are enabled for PostgreSQL flexible servers.',
    more_info: 'Enabling log_disconnections parameter records all activity data which helps in logging attempted and successful disconnections from the flexible server.',
    recommended_action: 'Ensure that server parameters for each PostgreSQL flexible server have log_disconnections setting enabled.',
    link: 'https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/how-to-configure-server-parameters-using-portal',
    apis: ['servers:listPostgresFlexibleServer', 'flexibleServersConfigurations:listByPostgresServer'],
    realtime_triggers: ['microsoftdbforpostgresql:flexibleservers:write','microsoftdbforpostgresql:flexibleservers:delete','microsoftdbforpostgresql:flexibleservers:configurations:write'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.servers, (location, rcb) => {
            const servers = helpers.addSource(cache, source,
                ['servers', 'listPostgresFlexibleServer', location]);

            if (!servers) return rcb();

            helpers.checkFlexibleServerConfigs(servers, cache, source, location, results, 'PostgreSQL Flexible', 'log_disconnections', 'Log disconnections');

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
