const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Log Disconnections Enabled',
    category: 'PostgreSQL Server',
    description: 'Ensures disconnection logs are enabled for PostgreSQL servers',
    more_info: 'Disconnection logs ensure all attempted and successful disconnections from the server are logged.',
    recommended_action: 'Ensure the server parameters for each PostgreSQL server have the log_disconnections setting enabled.',
    link: 'https://docs.microsoft.com/en-us/azure/postgresql/howto-configure-server-parameters-using-portal',
    apis: ['servers:listPostgres', 'configurations:listByServer'],
    compliance: {
        hipaa: 'HIPAA requires that a secure audit log record for ' +
            'write read and delete is created for all ' +
            'activities in the system.'
    },

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.servers, (location, rcb) => {
            const servers = helpers.addSource(cache, source,
                ['servers', 'listPostgres', location]);

            helpers.checkServerConfigs(servers, cache, source, location, results, 'PostgreSQL', 'log_disconnections', 'Disconnection logs');

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
