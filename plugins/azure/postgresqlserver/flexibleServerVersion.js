const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'PostgreSQL Flexible Server Version',
    category: 'PostgreSQL Server',
    domain: 'Databases',
    description: 'Ensure PostgreSQL flexible servers is using the latest server version.',
    more_info: 'The latest version of PostgreSQL for flexible servers will give access to new software features, resolve reported bugs through security patches, and improve compatibility with other applications and services.',
    recommended_action: 'Upgrade the version of PostgreSQL flexible server to the latest available version..',
    link: 'https://learn.microsoft.com/en-us/azure/postgresql/flexible-server/concepts-supported-versions',
    apis: ['servers:listPostgresFlexibleServer'],   
    settings: {
        server_desired_version: {
            name: 'Postgressql Flexible Server Desired Version',
            description: 'Desire Postgressql Flexible Server Version ',
            regex: '^[0-9]+$',
            default: '11'
        }
    },
    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);
        var config = {
            server_desired_version: settings.server_desired_version || this.settings.server_desired_version.default
        };


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

                if(flexibleServer.version >= config.server_desired_version) {
                    helpers.addResult(results, 0,
                        'Postgresql flexible server has the latest server version', location, flexibleServer.id);
                } else {
                    helpers.addResult(results, 2,
                        'Postgresql flexible server doesnot the latest server version', location, flexibleServer.id);
                }
            }
            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};