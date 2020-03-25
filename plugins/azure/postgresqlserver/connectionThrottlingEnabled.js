const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Connection Throttling Enabled',
    category: 'PostgreSQL Server',
    description: 'Ensures connection throttling is enabled for PostgreSQL servers',
    more_info: 'Connection throttling slows the amount of query and error logs sent by the server from the same IP address, limiting DoS attacks or the slowing down of servers due to excessive legitimate user logs.',
    recommended_action: 'Ensure the server parameters for each PostgreSQL server have the connection_throttling setting enabled.',
    link: 'https://docs.microsoft.com/en-us/azure/postgresql/howto-configure-server-parameters-using-portal',
    apis: ['servers:postgres:list', 'configurations:listByServer'],

    run: function (cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.servers.postgres, (location, rcb) => {

            const configurations = helpers.addSource(cache, source,
                ['configurations', 'listByServer', location]);

            if (!configurations) return rcb();

            if (configurations.err || !configurations.data) {
                helpers.addResult(results, 3,
                    'Unable to query for PostgreSQL Servers: ' + helpers.addError(configurations), location);
                return rcb();
            }

            if (!configurations.data.length) {
                helpers.addResult(results, 0, 'No existing PostgreSQL Servers found', location);
                return rcb();
            }

            var configuration = configurations.data.filter(config => {
                return config.name === "connection_throttling";
            });

            configuration.forEach(config => {
                var configIdArr = config.id.split('/');
                configIdArr.length = configIdArr.length - 2;
                var configId = configIdArr.join('/');

                if (config.value === 'ON' ||
                    config.value === 'on') {
                    helpers.addResult(results, 0, 'Connection throttling is enabled for the PostgreSQL Server configuration', location, configId);
                } else {
                    helpers.addResult(results, 2, 'Connection throttling is disabled for the PostgreSQL Server configuration', location, configId);
                }
            });

            rcb();
        }, function () {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
