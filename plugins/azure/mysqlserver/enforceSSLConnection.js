const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Enforce SSL Connection Enabled',
    category: 'MySQL Server',
    description: 'Ensures SSL connection is set on MySQL Servers.',
    more_info: 'SSL prevents infiltration attacks by encrypting the data stream between the server and app. By ensuring that SSL is enabled, security best practices are followed.',
    recommended_action: '1. Login to Azure Portal. 2. Go to Azure Database for MySQL server. 3. For each database, click on Connection security. 4. In SSL settings, Ensure Enforce SSL connection is set to Enabled.',
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
                    'Unable to query MySQL Server: ' + helpers.addError(servers), location);
                return rcb();
            }

            if (!servers.data.length) {
                helpers.addResult(results, 0, 'No existing MySQL Server', location);
                return rcb();
            }

            let allSslEnforced = true;

            for (let res in servers.data) {
                const mySQLServer = servers.data[res];

                if (mySQLServer.sslEnforcement && 
                    mySQLServer.sslEnforcement !== 'Enabled') {
                    helpers.addResult(results, 2,
                        'The MySQL Server is not enforced with SSL connection.', location, mySQLServer.name);
                    allSslEnforced = false;
                }
            }

            if (allSslEnforced) {
                helpers.addResult(results, 0, 'All MySQL Servers are enforced with SSL connection.', location);
            }
            rcb();
        }, function () {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
