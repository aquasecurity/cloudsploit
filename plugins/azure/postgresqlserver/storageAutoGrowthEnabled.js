const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Storage Auto Growth Enabled',
    category: 'PostgreSQL Server',
    description: 'Ensures that Storage Auto Growth is enabled for PostgreSQL servers',
    more_info: 'Storage Auto Growth must be enabled to accommodate the growing data',
    recommended_action: 'Enable Storage Auto Growth for PostgreSQL Server',
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
                const storageProfile = postgresServer.storageProfile;
                if (storageProfile) {
                    if (storageProfile.storageAutogrow &&
                        storageProfile.storageAutogrow.toLowerCase() == 'enabled') {
                            helpers.addResult(results, 0,
                                'Storage Auto Growth is enabled for PostgreSQL Server', location, postgresServer.id);
                    } else {
                        helpers.addResult(results, 2,
                            'Storage Auto Growth is not enabled for PostgreSQL Server', location, postgresServer.id);
                    }
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
