var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'App Service SCM Site Access Restriction',
    category: 'App Service',
    domain: 'Application Integration',
    description: 'Ensure that Azure App Services restrict access to the SCM site that\'s used by your app.',
    more_info: 'In addition to being able to control access to your app, you can restrict access to the SCM site that\'s used by your app. ' +
        'The SCM site is both the web deploy endpoint and the Kudu console.',
    recommended_action: 'Add access restriction rules under network settings for the scm site used by your app',
    link: 'https://docs.microsoft.com/en-us/azure/app-service/app-service-ip-restrictions#set-up-azure-functions-access-restrictions',
    apis: ['webApps:list', 'webApps:listConfigurations'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.webApps, function(location, rcb) {
            const webApps = helpers.addSource(cache, source,
                ['webApps', 'list', location]);

            if (!webApps) return rcb();

            if (webApps.err || !webApps.data) {
                helpers.addResult(results, 3, 'Unable to query for App Services : ' + helpers.addError(webApps), location);
                return rcb();
            }

            if (!webApps.data.length) {
                helpers.addResult(results, 0, 'No existing App Services found', location);
                return rcb();
            }

            webApps.data.forEach(webApp => {
                const webConfigs = helpers.addSource(
                    cache, source, ['webApps', 'listConfigurations', location, webApp.id]
                );

                if (!webConfigs || webConfigs.err || !webConfigs.data || !webConfigs.data.length) {
                    helpers.addResult(results, 3,
                        'Unable to query App Service configuration: ' + helpers.addError(webConfigs),
                        location, webApp.id);
                } else {
                    let denyAllIp;
                    if (webConfigs.data[0].scmIpSecurityRestrictions && webConfigs.data[0].scmIpSecurityRestrictions.length) {
                        denyAllIp = webConfigs.data[0].scmIpSecurityRestrictions.find(ipSecurityRestriction =>
                            ipSecurityRestriction.ipAddress && ipSecurityRestriction.ipAddress.toUpperCase() === 'ANY' &&
                            ipSecurityRestriction.action && ipSecurityRestriction.action.toUpperCase() === 'DENY'
                        );
                    }

                    if (denyAllIp) {
                        helpers.addResult(results, 0,
                            'App Service has access restriction enabled for scm site',
                            location, webApp.id);
                    } else {
                        helpers.addResult(results, 2, 'App Service does not have access restriction enabled for scm site', location, webApp.id);
                    }
                }
            });

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};