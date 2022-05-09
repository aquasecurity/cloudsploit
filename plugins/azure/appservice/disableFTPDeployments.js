const async = require('async');
const helpers = require('../../../helpers/azure/');

module.exports = {
    title: 'Disable FTP Deployments',
    category: 'App Service',
    domain: 'Application Integration',
    description: 'Ensures that FTP deployments are disabled for App Services.',
    more_info: 'Disabling FTP deployments ensures that the encrypted traffic between the web application server and the FTP client cannot be decrypted by malicious actors.',
    recommended_action: 'Disable FTP deployments in the general settings for all App Services.',
    link: 'https://docs.microsoft.com/en-us/azure/app-service/deploy-ftp?tabs=portal#enforce-ftps',
    apis: ['webApps:list', 'webApps:listConfigurations'],
    

    run: function(cache, settings, callback) {
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

            webApps.data.forEach(function(webApp) {
                const webConfigs = helpers.addSource(
                    cache, source, ['webApps', 'listConfigurations', location, webApp.id]
                );

                let ftpFound = false;

                if (!webConfigs || webConfigs.err || !webConfigs.data) {
                    helpers.addResult(results, 3,
                        'Unable to query App Service: ' + helpers.addError(webConfigs),
                        location, webApp.id);
                } else {
                    webConfigs.data.find((config) => {
                        if (config.ftpsState && config.ftpsState.toLowerCase() === 'allallowed') {
                            ftpFound = true;
                        }
                    });

                    if (ftpFound) {
                        helpers.addResult(results, 2, 'FTP deployments are not disabled for this web app', location, webApp.id);
                    } else {
                        helpers.addResult(results, 0, 'FTP deployments are disabled for this web app', location, webApp.id);
                    }
                }
            });

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
