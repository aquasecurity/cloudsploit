var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'OpenAI Account Diagnostic Logging Enabled',
    category: 'AI & ML',
    domain: 'Machine Learning',
    severity: 'Medium',
    description: 'Ensures that diagnostic logging is enabled for Azure OpenAI accounts.',
    more_info: 'Enabling diagnostic logs for Azure OpenAI accounts is crucial for monitoring and troubleshooting. It helps in tracking usage, detecting anomalies, and understanding API interactions, thereby enhancing the operational security and efficiency of AI applications.',
    recommended_action: 'Modify the OpenAI account settings and enable diagnostic logs.',
    link: 'https://learn.microsoft.com/en-us/azure/ai-services/openai/how-to/monitoring',
    apis: ['openAI:listAccounts', 'diagnosticSettings:listByOpenAIAccounts'],
    realtime_triggers: ['microsoftcognitiveservices:accounts:write','microsoftcognitiveservices:accounts:delete','microsoftinsights:diagnosticsettings:write','microsoftinsights:diagnosticsettings:delete'],

    run: function(cache, settings, callback) {
        const results = [];
        const source = {};
        const locations = helpers.locations(settings.govcloud);

        async.each(locations.openAI, function(location, rcb) {
            const accounts = helpers.addSource(cache, source,
                ['openAI', 'listAccounts', location]);

            if (!accounts) return rcb();


            if (accounts.err || !accounts.data) {
                helpers.addResult(results, 3, 'Unable to query OpenAI accounts: ' + helpers.addError(accounts), location);
                return rcb();
            }

            if (!accounts.data.length) {
                helpers.addResult(results, 0, 'No existing OpenAI accounts found', location);
                return rcb();
            }

            for (let account of accounts.data) {
                if (!account.id) continue;
                var diagnosticSettings = helpers.addSource(cache, source, 
                    ['diagnosticSettings', 'listByOpenAIAccounts', location, account.id]);
 
                if (!diagnosticSettings || diagnosticSettings.err || !diagnosticSettings.data) {
                    helpers.addResult(results, 3, `Unable to query for account diagnostic settings: ${helpers.addError(diagnosticSettings)}`,
                        location, account.id);
                    continue;
                }

                var found = diagnosticSettings.data.find(ds => ds.logs && ds.logs.length);

                if (found) {
                    helpers.addResult(results, 0, 'OpenAI account has diagnostic logs enabled', location, account.id);
                } else {
                    helpers.addResult(results, 2, 'OpenAI account does not have diagnostic logs enabled', location, account.id);
                }

            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};