const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'PostgreSQL Flexible Server Diagnostic Logging',
    category: 'PostgreSQL Server',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensures diagnostic logging is enabled for PostgreSQL flexible servers.',
    more_info: 'Enabling diagnostic logging for Azure Database for PostgreSQL flexible servers helps with performance monitoring, troubleshooting, and security optimization.',
    recommended_action: 'Enable diagnostic logging for all PostgreSQL servers.',
    link: 'https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-logging',
    apis: ['servers:listPostgresFlexibleServer', 'diagnosticSettings:listByPostgresFlexibleServers'],
    realtime_triggers: ['microsoftdbforpostgresql:flexibleservers:write', 'microsoftinsights:diagnosticsettings:write','microsoftinsights:diagnosticsettings:delete','microsoftdbforpostgresql:flexibleservers:delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.servers, (location, rcb) => {

            const servers = helpers.addSource(cache, source,
                ['servers', 'listPostgresFlexibleServer', location]);

            if (!servers) return rcb();

            if (servers.err || !servers.data) {
                helpers.addResult(results, 3,
                    'Unable to query for PostgreSQL Flexible Servers: ' + helpers.addError(servers), location);
                return rcb();
            }

            if (!servers.data.length) {
                helpers.addResult(results, 0, 'No existing PostgreSQL Flexible Servers found', location);
                return rcb();
            }

            for (let server of servers.data) {
                if (!server.id) continue;

                var diagnosticSettings = helpers.addSource(cache, source, 
                    ['diagnosticSettings', 'listByPostgresFlexibleServers', location, server.id]);
 
                if (!diagnosticSettings || diagnosticSettings.err || !diagnosticSettings.data) {
                    helpers.addResult(results, 3, `Unable to query for PostgreSQL Flexible Server diagnostic settings: ${helpers.addError(diagnosticSettings)}`,
                        location, server.id);
                    continue;
                }

                var found = diagnosticSettings.data.find(ds => ds.logs && ds.logs.length);

                if (found) {
                    helpers.addResult(results, 0, 'PostgreSQL Flexible Server has diagnostic logs enabled', location, server.id);
                } else {
                    helpers.addResult(results, 2, 'PostgreSQL Flexible Server does not have diagnostic logs enabled', location, server.id);
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};

