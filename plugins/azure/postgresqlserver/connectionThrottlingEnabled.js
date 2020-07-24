const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Connection Throttling Enabled',
    category: 'PostgreSQL Server',
    description: 'Ensures connection throttling is enabled for PostgreSQL servers',
    more_info: 'Connection throttling slows the amount of query and error logs sent by the server from the same IP address, limiting DoS attacks or the slowing down of servers due to excessive legitimate user logs.',
    recommended_action: 'Ensure the server parameters for each PostgreSQL server have the connection_throttling setting enabled.',
    link: 'https://docs.microsoft.com/en-us/azure/postgresql/howto-configure-server-parameters-using-portal',
    apis: ['servers:listPostgres', 'configurations:listByServer'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.servers, (location, rcb) => {
            const servers = helpers.addSource(cache, source,
                ['servers', 'listPostgres', location]);

            helpers.checkServerConfigs(servers, cache, source, location, results, 'PostgreSQL', 'connection_throttling', 'Connection throttling');
            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
