var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'OpenAI Account Has Tags',
    category: 'AI & ML',
    domain: 'Machine Learning',
    severity: 'Low',
    description: 'Ensures that Azure OpenAI accounts have tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    recommended_action: 'Modify Azure OpenAI accounts and add tags.',
    link: 'https://learn.microsoft.com/en-us/azure/azure-resource-manager/management/tag-resources',
    apis: ['openAI:listAccounts'],
    realtime_triggers: ['microsoftcognitiveservices:accounts:write','microsoftcognitiveservices:accounts:delete'],

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

                if (account.tags && Object.entries(account.tags).length > 0) {
                    helpers.addResult(results, 0,
                        'OpenAI Account has tags associated', location, account.id);
                } else {
                    helpers.addResult(results, 2,
                        'OpenAI Account does not have tags associated', location, account.id);
                }
            }

            rcb();
        }, function() {
            // Global checking goes here
            callback(null, results, source);
        });
    }
};