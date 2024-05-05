const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'PostgreSQL FLexible Server Connection Throttling Enabled',
    category: 'PostgreSQL Server',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensures that connection throttling is enabled for PostgreSQL flexible servers.',
    more_info: 'Enabling connection_throttle parameter for PostgreSQL flexible servers mitigates the risk of brute-force attacks by temporarily blocking IP addresses with multiple failed login attempts, enhancing security and server stability.',
    recommended_action: 'Ensures that server parameters for each PostgreSQL flexible server have connection_throttle setting enabled.',
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

            helpers.checkFlexibleServerConfigs(servers, cache, source, location, results, 'PostgreSQL Flexible', 'connection_throttle.enable', 'Connection throttling');

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
