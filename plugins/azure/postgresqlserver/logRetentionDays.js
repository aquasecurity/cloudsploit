const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Log Retention Period',
    category: 'PostgreSQL Server',
    description: 'Ensures logs are configured to be retained for 4 or more days for PostgreSQL servers',
    more_info: 'Having a long log retention policy ensures that all critical logs are stored for long enough to access and view in case of a security incident.',
    recommended_action: 'Ensure the server parameters for each PostgreSQL server have the log_retention_days setting set to 4 or more days.',
    link: 'https://docs.microsoft.com/en-us/azure/postgresql/howto-configure-server-parameters-using-portal',
    apis: ['servers:listPostgres', 'configurations:listByServer'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.servers, (location, rcb) => {
            const servers = helpers.addSource(cache, source,
                ['servers', 'listPostgres', location]);

            if (!servers) return rcb();

            if (servers.err || !servers.data) {
                helpers.addResult(results, 3,
                    'Unable to query for PostgreSQL Servers: ' + helpers.addError(servers), location);
                return rcb();
            }

            if (!servers.data.length) {
                helpers.addResult(results, 0, 'No existing PostgreSQL Servers found', location);
                return rcb();
            }

            servers.data.forEach(function(server) {
                const configurations = helpers.addSource(cache, source,
                    ['configurations', 'listByServer', location, server.id]);

                if (!configurations || configurations.err || !configurations.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for PostgreSQL Server configuration: ' + helpers.addError(configurations), location, server.id);
                } else {
                    var configuration = configurations.data.filter(config => {
                        return (config.name == 'log_retention_days');
                    });

                    if (configuration &&
                        configuration[0] &&
                        configuration[0].value &&
                        configuration[0].value > 3) {
                        helpers.addResult(results, 0, 'Log retention period is greater than 3 days', location, server.id);
                    } else {
                        helpers.addResult(results, 2, 'Log retention period is 3 days or less or is not set', location, server.id);
                    }
                }
            });

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
