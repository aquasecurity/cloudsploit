const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'MySQL Flexible Server Diagnostic Logs',
    category: 'MySQL Server',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensures that MySQL flexible server has diagnostic logs enabled.',
    more_info: 'Enabling diagnostic logging for Azure Database for MySQL Flexible servers helps with performance monitoring, troubleshooting, and security optimization.',
    recommended_action: 'Enable diagnostic logging for all MySQL flexible servers.',
    link: 'https://learn.microsoft.com/en-us/azure/mysql/flexible-server/concepts-monitoring',
    apis: ['servers:listMysqlFlexibleServer', 'diagnosticSettings:listByMysqlFlexibleServer'],
    realtime_triggers: ['microsoftdbformysql:flexibleservers:write','microsoftdbformysql:flexibleservers:delete','microsoftinsights:diagnosticsettings:write','microsoftinsights:diagnosticsettings:delete'],

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

            for (let server of servers.data) {
                if (!server.id) continue;

                var diagnosticSettings = helpers.addSource(cache, source, 
                    ['diagnosticSettings', 'listByMysqlFlexibleServer', location, server.id]);
 
                if (!diagnosticSettings || diagnosticSettings.err || !diagnosticSettings.data) {
                    helpers.addResult(results, 3, `Unable to query for MySQL flexible server diagnostic settings: ${helpers.addError(diagnosticSettings)}`,
                        location, server.id);
                    continue;
                }

                var found = diagnosticSettings.data.find(ds => ds.logs && ds.logs.length);

                if (found) {
                    helpers.addResult(results, 0, 'MySQL flexible server has diagnostic logs enabled', location, server.id);
                } else {
                    helpers.addResult(results, 2, 'MySQL flexible server does not have diagnostic logs enabled', location, server.id);
                }
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
