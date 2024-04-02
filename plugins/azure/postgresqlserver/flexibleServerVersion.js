const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'PostgreSQL Flexible Server Version',
    category: 'PostgreSQL Server',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensure PostgreSQL flexible servers is using the latest server version.',
    more_info: 'Using the latest version of PostgreSQL for flexible servers will give access to new software features, resolve reported bugs through security patches, and improve compatibility with other applications and services.',
    recommended_action: 'Upgrade the version of PostgreSQL flexible server to the latest available version.',
    link: 'https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-supported-versions',
    apis: ['servers:listPostgresFlexibleServer'],
    realtime_triggers: ['microsoftdbforpostgresql:flexibleservers:write','microsoftdbforpostgresql:flexibleservers:delete',],

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
                    'Unable to query for PostgreSQL flexible servers: ' + helpers.addError(servers), location);
                return rcb();
            }

            if (!servers.data.length) {
                helpers.addResult(results, 0, 'No existing PostgreSQL flexible servers found', location);
                return rcb();
            }

            for (var flexibleServer of servers.data) {
                if (!flexibleServer.id || !flexibleServer.version) continue;
                
                let version = parseFloat(flexibleServer.version);

                if (version && version >= 13) {
                    helpers.addResult(results, 0,
                        'PostgreSQL flexible server has the latest server version', location, flexibleServer.id);
                } else {
                    helpers.addResult(results, 2,
                        'PostgreSQL flexible server does not the latest server version', location, flexibleServer.id);
                }
            }
            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
