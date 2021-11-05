const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Storage Auto-Growth Enabled',
    category: 'PostgreSQL Server',
    domain: 'Databases',
    description: 'Ensures that Storage Auto-Growth feature is enabled for Microsoft Azure PostgreSQL servers.',
    more_info: 'Storage auto grow prevents your server from reaching the storage limit and becoming read-only. For servers with 100 GB or less of provisioned storage, the size is increased by 5 GB when the free space is below 10%. For servers with more than 100 GB of provisioned storage, the size is increased by 5% when the free space is below 10 GB.',
    recommended_action: 'Modify PostgreSQL servers to enable storage auto-growth feature',
    link: 'https://docs.microsoft.com/en-us/azure/postgresql/howto-auto-grow-storage-portal',
    apis: ['servers:listPostgres'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.servers, (location, rcb) => {

            const listPostgres = helpers.addSource(cache, source,
                ['servers', 'listPostgres', location]);

            if (!listPostgres) return rcb();

            if (listPostgres.err || !listPostgres.data) {
                helpers.addResult(results, 3,
                    'Unable to query for PostgreSQL Servers: ' + helpers.addError(listPostgres), location);
                return rcb();
            }

            if (!listPostgres.data.length) {
                helpers.addResult(results, 0, 'No existing PostgreSQL Servers found', location);
                return rcb();
            }

            for (let postgresServer of listPostgres.data) {
                if (postgresServer.storageProfile &&
                    postgresServer.storageProfile.storageAutogrow && 
                    postgresServer.storageProfile.storageAutogrow.toLowerCase() == 'enabled') {
                    helpers.addResult(results, 0,
                        'Storage Auto Growth is enabled for PostgreSQL Server', location, postgresServer.id);
                } else {
                    helpers.addResult(results, 2,
                        'Storage Auto Growth is not enabled for PostgreSQL Server', location, postgresServer.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
