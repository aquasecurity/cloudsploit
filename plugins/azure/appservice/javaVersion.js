var async = require('async');
var helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Java Version',
    category: 'App Service',
    domain: 'Application Integration',
    description: 'Ensures the latest version of Java is installed for all App Services',
    more_info: 'Installing the latest version of Java will reduce the security risk of missing security patches.',
    recommended_action: 'Select the latest version of Java for all Java-based App Services',
    link: 'https://docs.microsoft.com/en-us/azure/app-service/app-service-web-get-started-java',
    apis: ['webApps:list', 'webApps:listConfigurations'],
    settings: {
        latestJavaVersion: {
            name: 'Latest Java Version',
            default: 17,
            description: 'The latest Java version supported by Azure App Service.',
            regex: '[0-9.]{2,5}'
        }
    },

    run: function(cache, settings, callback) {
        const config = {
            latestJavaVersion: settings.latestJavaVersion || this.settings.latestJavaVersion.default
        };

        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.webApps, function(location, rcb) {
            const webApps = helpers.addSource(
                cache, source, ['webApps', 'list', location]
            );

            if (!webApps) return rcb();

            if (webApps.err || !webApps.data) {
                helpers.addResult(results, 3,
                    'Unable to query list web apps: ' + helpers.addError(webApps), location);
                return rcb();
            }

            if (!webApps.data.length) {
                helpers.addResult(
                    results, 0, 'No existing App Services found', location);
                return rcb();
            }
            let found = false;
            for (let webApp of webApps.data) {
                const webConfigs = helpers.addSource(
                    cache, source, ['webApps', 'listConfigurations', location, webApp.id]);
                if (!webConfigs || webConfigs.err || !webConfigs.data || !webConfigs.data.length) {
                    helpers.addResult(results, 3,
                        'Unable to query list web app configurations: ' + helpers.addError(webConfigs),
                        location, webApp.id);
                    continue;
                }

                var appConfig = webConfigs.data[0];
                let versionAvailable = false, currentVersion;
                if (webApp.kind && webApp.kind === 'app'){
                    // windows app
                    if (appConfig.javaContainer && appConfig.javaContainer.toLowerCase() === 'java'){
                        found  = true;
                        currentVersion = appConfig.javaVersion;
                        if (appConfig.javaVersion && parseFloat(appConfig.javaVersion) >= parseFloat(config.latestJavaVersion)){
                            versionAvailable = true;
                        }
                    } 
                } else {
                    // linux app
                    if (appConfig.linuxFxVersion &&
                    (appConfig.linuxFxVersion.toLowerCase().indexOf('java') > -1)){
                        found = true;
                        let version = appConfig.linuxFxVersion;
                        currentVersion = appConfig.linuxFxVersion.substring(version.indexOf('|')+1, version.lastIndexOf('-'));
                        if (currentVersion && currentVersion != '' && parseFloat(currentVersion) >= parseFloat(config.latestJavaVersion)){
                            versionAvailable = true;
                        }
                    }
                }
                if (found){
                    if (versionAvailable) {
                        helpers.addResult(results, 0, `The Java version (${currentVersion}) is the latest version`, location, webApp.id);
                    } else {
                        helpers.addResult(results, 2, `The Java version (${currentVersion}) is not the latest version`, location, webApp.id);
                    } 
                }
            }
            if (!found) {
                helpers.addResult(results, 0, 'No App Services with Java found', location);
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
