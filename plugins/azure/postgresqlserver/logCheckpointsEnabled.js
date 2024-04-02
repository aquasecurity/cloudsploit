const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Log Checkpoints Enabled',
    category: 'PostgreSQL Server',
    domain: 'Databases',
    severity: 'Low',
    description: 'Ensures log checkpoints are enabled for PostgreSQL servers',
    more_info: 'Log checkpoints logs queries and errors that arise in the server, enabling faster detection of incidents.',
    recommended_action: 'Ensure the server parameters for each PostgreSQL server have the log_checkpoints setting enabled.',
    link: 'https://learn.microsoft.com/en-us/azure/postgresql/howto-configure-server-parameters-using-portal',
    apis: ['servers:listPostgres', 'configurations:listByServer'],
    compliance: {
        hipaa: 'HIPAA requires that a secure audit log record for ' +
            'write read and delete is created for all ' +
            'activities in the system.'
    },
    realtime_triggers: ['microsoftdbforpostgresql:servers:write','microsoftdbforpostgresql:servers:delete','microsoft.dbforpostgresql:servers:configurations:write'],

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
