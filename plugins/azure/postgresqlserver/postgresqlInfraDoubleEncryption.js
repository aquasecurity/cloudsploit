const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'PostgreSQL Infrastructure Double Encryption',
    category: 'PostgreSQL Server',
    domain: 'Databases',
    description: 'Ensures Infrastructure double encryption is enabled for PostgreSQL Database Servers.',
    more_info: 'Double Encryption adds layer of encryption is implemented at the hardware level before the storage or network level. Information will be encrypted before it is even accessed, preventing both interception of data in motion if the network layer encryption is broken and data at rest in system resources such as memory or processor cache.',
    recommended_action: 'Enable Infrastructure double encryotion for PostgreSQL database servers.',
    link: 'https://docs.microsoft.com/en-us/azure/postgresql/howto-double-encryption',
    apis: ['servers:listPostgres'],

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
                    'Unable to query for PostgreSQL servers: ' + helpers.addError(servers), location);
                return rcb();
            }

            if (!servers.data.length) {
                helpers.addResult(results, 0, 'No existing PostgreSQL servers found', location);
                return rcb();
            }

            for (let postgresqlDB of servers.data) {
                if (!postgresqlDB.id) continue;

                if (postgresqlDB.infrastructureEncryption &&
                   postgresqlDB.infrastructureEncryption.toLowerCase() === 'enabled') {
                    helpers.addResult(results, 0,
                        'Infrastructure double encryption is enabled for PostgreSQL server', location, postgresqlDB.id);
                } else {
                    helpers.addResult(results, 2,
                        'Infrastructure double encryption is not enabled for PostgreSQL server', location, postgresqlDB.id);
                }
            }
           
            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
