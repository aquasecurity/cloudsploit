const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Enforce SSL Connection Enabled',
    category: 'MySQL Server',
    description: 'Ensures SSL connection is enforced on MySQL servers',
    more_info: 'MySQL servers should be set to use SSL for data transmission to ensure all data is encrypted in transit.',
    recommended_action: 'Ensure the connection security of each Azure Database for MySQL is configured to enforce SSL connections.',
    link: 'https://docs.microsoft.com/en-us/azure/mysql/concepts-ssl-connection-security',
    apis: ['servers:mysql:list'],

    run: function (cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.servers.mysql, (location, rcb) => {

            const servers = helpers.addSource(cache, source,
                ['servers', 'mysql', 'list', location]);

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

            let allSslEnforced = true;

            for (let res in servers.data) {
                const mySQLServer = servers.data[res];

                if (mySQLServer.sslEnforcement && 
                    mySQLServer.sslEnforcement !== 'Enabled') {
                    helpers.addResult(results, 2,
                        'The MySQL server does not enforce SSL connections', location, mySQLServer.name);
                    allSslEnforced = false;
                }
            }

            if (allSslEnforced) {
                helpers.addResult(results, 0, 'All MySQL servers enforce SSL connections', location);
            }
            rcb();
        }, function () {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
