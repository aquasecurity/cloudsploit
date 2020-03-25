const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Log Duration Enabled',
    category: 'PostgreSQL Server',
    description: 'Ensures connection duration logs are enabled for PostgreSQL servers',
    more_info: 'Connection duration logs log duration times of connections to the server and can be used to locate suspicious long-running connections.',
    recommended_action: 'Ensure the server parameters for each PostgreSQL server have the log_duration setting enabled.',
    link: 'https://docs.microsoft.com/en-us/azure/postgresql/howto-configure-server-parameters-using-portal',
    apis: ['servers:postgres:list', 'configurations:listByServer'],
    compliance: {
        hipaa: 'HIPAA requires that a secure audit log record for ' +
            'write read and delete is created for all ' +
            'activities in the system.'
    },

    run: function (cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.servers.postgres, (location, rcb) => {

            const configurations = helpers.addSource(cache, source,
                ['configurations', 'listByServer', location]);

            if (!configurations) return rcb();

            if (configurations.err || !configurations.data) {
                helpers.addResult(results, 3,
                    'Unable to query for PostgreSQL Servers: ' + helpers.addError(configurations), location);
                return rcb();
            }

            if (!configurations.data.length) {
                helpers.addResult(results, 0, 'No existing PostgreSQL Servers found', location);
                return rcb();
            }

            var configuration = configurations.data.filter(config => {
                return config.name === "log_duration";
            });

            configuration.forEach(config => {
                var configIdArr = config.id.split('/');
                configIdArr.length = configIdArr.length - 2;
                var configId = configIdArr.join('/');

                if (config.value === 'ON' ||
                    config.value === 'on') {
                    helpers.addResult(results, 0, 'Duration logs are enabled for the PostgreSQL Server configuration', location, configId);
                } else {
                    helpers.addResult(results, 2, 'Duration logs are disabled for the PostgreSQL Server configuration', location, configId);
                }
            });


            rcb();
        }, function () {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
