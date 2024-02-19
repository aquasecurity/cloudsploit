var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Secure Azure Http Triggered Function',
    category: 'App Service',
    domain: 'Application Integration',
    severity: 'Medium',
    description: 'Ensures that the authorization level function is set on Azure HTTP trigger functions.',
    more_info: 'Authorization levels for HTTP-triggered functions helps establish a secure access control framework during development and provides flexibility to enhance security in production by considering alternative measures beyond basic API access keys.',
    recommended_action: 'Set the authorization level for all HTTP-triggered functions.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-functions/security-concepts?tabs=v4#authorization-scopes-function-level',
    apis: ['webApps:list', 'functions:list'],
    realtime_triggers: ['microsoftweb:sites:write','microsoftweb:sites:delete', 'microsoftweb:sites:functions:write', 'microsoftweb:sites:functions:delete'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.webApps, function(location, rcb) {
            const appService = helpers.addSource(cache, source,
                ['webApps', 'list', location]);

            if (!appService) return rcb();

            if (appService.err || !appService.data) {
                helpers.addResult(results, 3, 'Unable to query for App Services' + helpers.addError(appService), location);
                return rcb();
            }

            if (!appService.data.length) {
                helpers.addResult(results, 0, 'No existing App Service found', location);
                return rcb();
            }

            async.each(appService.data, function(app, scb) {
                if (app && app.kind && app.kind.startsWith('functionapp')){
                    const functions = helpers.addSource(cache, source,
                        ['functions', 'list', location, app.id]);
    
                    if (!functions || functions.err || !functions.data) {
                        helpers.addResult(results, 3, 'Unable to query Azure Functions for app service: ' + helpers.addError(functions), location);
                        return scb();
                    }
                    if (!functions.data.length) {
                        helpers.addResult(results, 0, 'No existing Functions found for App Service', location, app.id);
                        return scb();
                    }
                    for (let func of functions.data) {
                        if (func && func.config && func.config.bindings && func.config.bindings.length > 0) {
                            const httpTriggerBindings = func.config.bindings.filter(binding => binding.type === 'httpTrigger');

                            if (httpTriggerBindings.length) {
                                for (const httpTriggerBinding of httpTriggerBindings) {
                                    // Check Authorization Level for each httpTrigger binding
                                    if (httpTriggerBinding.authLevel && httpTriggerBinding.authLevel.toLowerCase() === 'function') {
                                        helpers.addResult(results, 0, 'HTTP triggered function has secured authorization Level', location, func.id);
                                    } else {
                                        helpers.addResult(results, 2, 'HTTP triggered function does not have secured authorization Level', location, func.id);
                                    }
                                }
                            } else {
                                // Not an HTTP trigger function
                                helpers.addResult(results, 0, 'Function is not an HTTP triggered function', location, func.id);
                            }
                        }
                    }
                   
                }  else {
                    helpers.addResult(results, 0, 'Http triggered functions can not be configured for web app', location, appService.id);
                }
                scb();
            }, function() {
                rcb();
            });
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
