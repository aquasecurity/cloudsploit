const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Infrastructure Double Encryption',
    category: 'PostgreSQL Server',
    domain: 'Databases',
    description: 'Ensures Infrastructure double encryption is enabled for PostgreSQL Database Servers.',
    more_info: 'If Double Encryption is enabled, another layer of encryption is implemented at the hardware level before the storage or network level. Information will be encrypted before it is even accessed, preventing both interception of data in motion if the network layer encryption is broken and data at rest in system resources such as memory or processor cache. Encryption will also be in place for any backups taken of the database, so the key will secure access the data in all forms. For the most secure implementation of key based encryption, it is recommended to use a Customer Managed asymmetric RSA 2048 Key in Azure Key Vault.',
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
                    'Unable to query for PostgreSQL Servers: ' + helpers.addError(servers), location);
                return rcb();
            }

            if (!servers.data.length) {
                helpers.addResult(results, 0, 'No existing PostgreSQL Servers found', location);
                return rcb();
            }

            for (let postgresqlDB of servers.data) {
              
                if(postgresqlDB.infrastructureEncryption &&
                   postgresqlDB.infrastructureEncryption.toLowerCase() === 'enabled') {
                    helpers.addResult(results, 0,
                        'Infrastructure double encryption is enabled for PostgreSQL Server', location, postgresqlDB.id);
                } else {
                    helpers.addResult(results, 2,
                        'Infrastructure double encryption is not enabled for PostgreSQL Server', location, postgresqlDB.id);
                }
            }
           
            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
