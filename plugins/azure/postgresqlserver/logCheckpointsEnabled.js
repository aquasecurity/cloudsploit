const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Log Checkpoints Enabled',
    category: 'PostgreSQL Server',
    description: 'Ensures log checkpoints are enabled for PostgreSQL servers',
    more_info: 'Log checkpoints logs queries and errors that arise in the server, enabling faster detection of incidents.',
    recommended_action: 'Ensure the server parameters for each PostgreSQL server have the log_checkpoints setting enabled.',
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

            helpers.checkServerConfigs(servers, cache, source, location, results, 'PostgreSQL', 'log_checkpoints', 'Log Checkpoints');

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
