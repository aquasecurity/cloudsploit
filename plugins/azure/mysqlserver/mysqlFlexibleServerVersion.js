const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'MySQL Flexible Server Version',
    category: 'MySQL Server',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensures that MySQL Flexible Servers are using the latest server version.',
    more_info: 'Using the latest version of Upgrade the version of MySQL flexible server to the latest available version will give access to new software features, resolve reported bugs through security patches, and improve compatibility with other applications and services.',
    recommended_action: 'Ensure MySQL Flexible Servers are using the latest server version.',
    link: 'https://learn.microsoft.com/en-us/azure/mysql/flexible-server/how-to-upgrade',
    apis: ['servers:listMysqlFlexibleServer'],   
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
                if (!flexibleServer.id || !flexibleServer.version) continue;

                let version = parseFloat(flexibleServer.version);
            
                if (version && version >= 8.0) {
                    helpers.addResult(results, 0,
                        'MySQL flexible server has latest server version', location, flexibleServer.id);
                } else {
                    helpers.addResult(results, 2,
                        'MySQL flexible server does not have latest server version', location, flexibleServer.id);
                }
            }
            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};