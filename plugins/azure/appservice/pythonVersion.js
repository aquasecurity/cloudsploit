const async = require('async');
const helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Python Version',
    category: 'App Service',
    description: 'Ensure the latest version of Python is installed on all App Services.',
    more_info: 'Installing the latest version of Python will reduce the security risk of missing security patches.',
    recommended_action: 'Set python version to the latest version on all your App Services',
    link: 'https://docs.microsoft.com/en-us/azure/app-service/containers/how-to-configure-python',
    apis: ['webApps:list', 'webApps:listConfigurations'],
    settings: {
        latestPythonVersion: {
            name: 'Latest Python Version',
            default: 3.6
        }
    },

    run: function (cache, settings, callback) {

        const configuration = {
            latestPythonVersion: settings.latestPythonVersion || this.settings.latestPythonVersion.default
        };

        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.webApps, function (location, rcb) {

            const webApps = helpers.addSource(
                cache, source, ['webApps', 'listConfigurations', location]
            );

            if (!webApps) return rcb();

            if (webApps.err || !webApps.data) {
                helpers.addResult(results, 3,
                    'Unable to query App services: ' + helpers.addError(webApps), location);
                return rcb();
            }

            if (!webApps.data.length) {
                helpers.addResult(results, 0, 'No existing App services', location);
                return rcb();
            }

            var pythonVersionCheck = [];

            webApps.data.forEach(function(webApp){
                if (webApp.linuxFxVersion.indexOf('PYTHON')>-1 &&
                    webApp.linuxFxVersion.indexOf('|')>-1){
                    var pythonVersion = webApp.linuxFxVersion.substr(webApp.linuxFxVersion.indexOf('|')+1);
                    if (parseFloat(pythonVersion) < configuration.latestPythonVersion) {
                        pythonVersionCheck.push({'id':webApp.id, 'version':pythonVersion});
                    }
                }
            });

            if (pythonVersionCheck.length > 20) {
                helpers.addResult(results, 2, 'More than 20 App services have an outdated version of Python', location);
            } else if (pythonVersionCheck.length) {
                for (app in pythonVersionCheck) {
                    helpers.addResult(results, 2, `Python version is outdated (${pythonVersionCheck[app].version})`, location, pythonVersionCheck[app].id);
                }
            } else {
                helpers.addResult(results, 0, 'All Python App services are running on the latest version', location);
            }

            rcb();
        }, function () {
            // Global checking goes here
            callback(null, results, source);
        });
    }
}
