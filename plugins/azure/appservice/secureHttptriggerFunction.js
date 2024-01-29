var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Secure Azure Http Trigger Function',
    category: 'App Service',
    domain: 'Application Integration',
    description: 'Ensures that the Authorization Level function is set on the Azure HTTP trigger functions.',
    more_info: 'Authorization levels for HTTP-triggered functions helps establish a secure access control framework during development and provides flexibility to enhance security in production by considering alternative measures beyond basic API access keys.',
    recommended_action: 'Set the Authorization Level of a HTTP trigger function to enum Function',
    link: 'https://learn.microsoft.com/en-us/azure/azure-functions/security-concepts?tabs=v4#authorization-scopes-function-level',
    apis: ['webApps:list', 'functions:list'],

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
                if (app && app.kind && app.kind === 'functionapp') {
                    const functions = helpers.addSource(cache, source,
                        ['functions', 'list', location, app.id]);
    
                    if (!functions || functions.err || !functions.data) {
                        helpers.addResult(results, 3, 'Unable to query for Azure Functions: ' + helpers.addError(functions), location);
                        return scb();
                    }
                    if (!functions.data.length) {
                        helpers.addResult(results, 0, 'No existing Function found', location, appService.id);
                        return scb();
                    }
                    for (let func of functions.data) {
                        if (func && func.config && func.config.bindings && func.config.bindings.length > 0) {
                            const firstBinding = func.config.bindings[0];
                            if (firstBinding && firstBinding.type === 'httpTrigger') {
                                // Check Authorization Level
                                if (firstBinding.authLevel === 'function') {
                                    helpers.addResult(results, 0, 'Authorization Level is set to Function for HTTP trigger function', location, func.id);
                                } else {
                                    helpers.addResult(results, 2, 'Authorization Level is not set to Function for HTTP trigger function', location, func.idfunc);
                                }
                            } else {
                                // Not an HTTP trigger function
                                helpers.addResult(results, 0, 'Function is not an HTTP trigger', location, func.id);
                            }
                        }
                    }
                   
                }  else {
                    helpers.addResult(results, 0, 'Http trigger function can not be configured for web app', location, appService.id);
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
