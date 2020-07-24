const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Enforce MySQL SSL Connection',
    category: 'MySQL Server',
    description: 'Ensures SSL connection is enforced on MySQL servers',
    more_info: 'MySQL servers should be set to use SSL for data transmission to ensure all data is encrypted in transit.',
    recommended_action: 'Ensure the connection security of each Azure Database for MySQL is configured to enforce SSL connections.',
    link: 'https://docs.microsoft.com/en-us/azure/mysql/concepts-ssl-connection-security',
    apis: ['servers:listMysql'],
    compliance: {
        hipaa: 'HIPAA requires all data to be transmitted over secure channels. ' +
            'MySQL SSL connection should be used to ensure internal ' +
            'services are always connecting over a secure channel.',
    },

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.servers, (location, rcb) => {

            const servers = helpers.addSource(cache, source,
                ['servers', 'listMysql', location]);

            if (!servers) return rcb();

            if (servers.err || !servers.data) {
                helpers.addResult(results, 3,
                    'Unable to query for MySQL servers: ' + helpers.addError(servers), location);
                return rcb();
            }

            if (!servers.data.length) {
                helpers.addResult(results, 0, 'No existing MySQL servers found', location);
                return rcb();
            }

            servers.data.forEach(function(server) {
                if (server.sslEnforcement &&
                    server.sslEnforcement.toLowerCase() == 'enabled') {
                    helpers.addResult(results, 0,
                        'The MySQL server enforces SSL connections', location, server.id);
                } else {
                    helpers.addResult(results, 2,
                        'The MySQL server does not enforce SSL connections', location, server.id);
                } 
            });

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
