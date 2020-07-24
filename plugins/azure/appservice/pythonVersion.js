const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Python Version',
    category: 'App Service',
    description: 'Ensures the latest version of Python is installed for all App Services',
    more_info: 'Installing the latest version of Python will reduce the security risk of missing security patches.',
    recommended_action: 'Select the latest version of Python for all Python-based App Services',
    link: 'https://docs.microsoft.com/en-us/azure/app-service/containers/how-to-configure-python',
    apis: ['webApps:list', 'webApps:listConfigurations'],
    settings: {
        latestPythonVersion: {
            name: 'Latest Python Version',
            default: '3.6',
            description: 'The latest Python version supported by Azure App Service.',
            regex: '[0-9.]{2,5}'
        }
    },

    run: function(cache, settings, callback) {
        const config = {
            latestPythonVersion: settings.latestPythonVersion || this.settings.latestPythonVersion.default
        };

        var custom = helpers.isCustom(settings, this.settings);

        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.webApps, function(location, rcb) {
            const webApps = helpers.addSource(
                cache, source, ['webApps', 'list', location]
            );

            if (!webApps) return rcb();

            if (webApps.err || !webApps.data) {
                helpers.addResult(results, 3,
                    'Unable to query for App Services: ' + helpers.addError(webApps), location);
                return rcb();
            }

            if (!webApps.data.length) {
                helpers.addResult(
                    results, 0, 'No existing App Services found', location);
                return rcb();
            }

            var found = false;

            webApps.data.forEach(function(webApp) {
                const webConfigs = helpers.addSource(
                    cache, source, ['webApps', 'listConfigurations', location, webApp.id]
                );

                if (!webConfigs || webConfigs.err || !webConfigs.data) {
                    helpers.addResult(results, 3,
                        'Unable to query App Service: ' + helpers.addError(webConfigs),
                        location, webApp.id);
                } else {
                    if (webConfigs.data[0] &&
                        webConfigs.data[0].linuxFxVersion &&
                        webConfigs.data[0].linuxFxVersion.indexOf('PYTHON') > -1 &&
                        webConfigs.data[0].linuxFxVersion.indexOf('|') > -1) {
                        found = true;

                        var pythonVersion = webConfigs.data[0].linuxFxVersion.substr(webConfigs.data[0].linuxFxVersion.indexOf('|') + 1);

                        var version = parseFloat(pythonVersion);
                        var allowedVersion = parseFloat(config.latestPythonVersion);

                        if (version >= allowedVersion) {
                            helpers.addResult(results, 0,
                                `The Python version (${pythonVersion}) is the latest version`, location, webApp.id, custom);
                        } else {
                            helpers.addResult(results, 2,
                                `The Python version (${pythonVersion}) is not the latest version`, location, webApp.id, custom);
                        }
                    }
                }
            });

            if (!found) {
                helpers.addResult(results, 0, 'No App Services with Python found', location);
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
