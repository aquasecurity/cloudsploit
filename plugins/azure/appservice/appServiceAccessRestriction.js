var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'App Service Access Restriction',
    category: 'App Service',
    domain: 'Application Integration',
    description: 'Ensure that Azure App Services have access restriction configured to control network access to your app.',
    more_info: 'By setting up access restrictions, you can define a priority-ordered allow/deny list that controls network access to your app. ' + 
        'The list can include IP addresses or Azure Virtual Network subnets. When there are one or more entries, an implicit deny all exists at the end of the list.',
    recommended_action: 'Add access restriction rules under network settings for the app services',
    link: 'https://docs.microsoft.com/en-us/azure/app-service/app-service-ip-restrictions#set-up-azure-functions-access-restrictions',
    apis: ['webApps:list', 'webApps:listConfigurations'],
    remediation_min_version: '202201131602',
    remediation_description: 'Access restriction rule will be added to deny access from any source for affected app services',
    apis_remediate: ['webApps:list', 'webApps:listConfigurations'],
    actions: {remediate:['webApps:updateconfiguration'], rollback:['webApps:updateconfiguration']},
    permissions: {remediate: ['webApps:updateconfiguration'], rollback: ['webApps:updateconfiguration']},
    realtime_triggers: ['microsoftweb:sites:config:write'],

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
                    if (webConfigs.data[0].ipSecurityRestrictions && webConfigs.data[0].ipSecurityRestrictions.length) {
                        denyAllIp = webConfigs.data[0].ipSecurityRestrictions.find(ipSecurityRestriction =>
                            ipSecurityRestriction.ipAddress && ipSecurityRestriction.ipAddress.toUpperCase() === 'ANY' &&
                            ipSecurityRestriction.action && ipSecurityRestriction.action.toUpperCase() === 'DENY'
                        );
                    }

                    if (denyAllIp) {
                        helpers.addResult(results, 0,
                            'App Service has access restriction enabled',
                            location, webApp.id);
                    } else {
                        helpers.addResult(results, 2, 'App Service does not have access restriction enabled', location, webApp.id);
                    }
                }
            });

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    },
    remediate: function(config, cache, settings, resource, callback) {
        var remediation_file = settings.remediation_file;
        var putCall = this.actions.remediate;

        // inputs specific to the plugin
        var pluginName = 'appServiceAccessRestriction';
        var baseUrl = 'https://management.azure.com/{resource}/config/web?api-version=2021-02-01';
        var method = 'PATCH';

        // for logging purposes
        var webAppNameArr = resource.split('/');
        var webAppName = webAppNameArr[webAppNameArr.length - 1];

        // create the params necessary for the remediation
        if (settings.region) {
            var body = {
                'location': settings.region,
                'properties': {
                    'ipSecurityRestrictions': [
                        {
                            'action': 'Deny',
                            'name': 'Deny All Access',
                            'ipAddress': '0.0.0.0/0',
                            'description': 'Aqua CSPM Auto Remediation',
                            'priority': 2147483647
                        }
                    ]
                }

            };

            // logging
            remediation_file['pre_remediate']['actions'][pluginName][resource] = {
                'AccessRestriction': 'Disabled',
                'WebApp': webAppName
            };

            helpers.remediatePlugin(config, method, body, baseUrl, resource, remediation_file, putCall, pluginName, function(err, action) {
                if (err) {
                    console.log(err);
                    return callback(err);
                }
                if (action) action.action = putCall;


                remediation_file['post_remediate']['actions'][pluginName][resource] = action;
                remediation_file['remediate']['actions'][pluginName][resource] = {
                    'Action': 'Enabled'
                };

                callback(null, action);
            });
        } else {
            callback('No region found');
        }
    }
};
