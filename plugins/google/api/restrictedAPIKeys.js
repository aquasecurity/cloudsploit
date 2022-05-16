var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Restricted API Keys',
    category: 'API',
    domain: 'Identity and Access Management',
    description: 'Ensure that your Google Cloud API Keys are restricted to only those APIs that your application needs access to.',
    more_info: 'API keys are unrestricted by default. Unrestricted keys are insecure because they can be used by anyone from anywhere. To reduce the risk of attacks, Google Cloud API keys should be restricted to call only the APIs required by your application.',
    link: 'https://cloud.google.com/docs/authentication/api-keys#api_key_restrictions',
    recommended_action: 'Ensure that API restrictions are set for all Google Cloud API Keys.',
    apis: ['apiKeys:list', 'projects:get'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        let projects = helpers.addSource(cache, source,
            ['projects', 'get', 'global']);

        if (!projects || projects.err || !projects.data) {
            helpers.addResult(results, 3,
                'Unable to query for projects: ' + helpers.addError(projects), 'global', null, null, projects.err);
            return callback(null, results, source);
        }

        let apiKeys = helpers.addSource(cache, source,
            ['apiKeys', 'list', 'global']);
    
        if (!apiKeys) return callback(null, results, source);

        if (apiKeys.err || !apiKeys.data) {
            helpers.addResult(results, 3, 'Unable to query API Keys for project', 'global', null, null, apiKeys.err);
            return callback(null, results, source);
        }

        if (!apiKeys.data.length) {
            helpers.addResult(results, 0, 'No API Keys found', 'global');
            return callback(null, results, source);
        }

        apiKeys.data.forEach(key => {            
            if (key.restrictions && key.restrictions.apiTargets && key.restrictions.apiTargets.length && 
                !key.restrictions.apiTargets.find(target => target.service && target.service === 'cloudapis.googleapis.com')) {
                helpers.addResult(results, 0,
                    'API Key is restricted', 'global', key.name);
            } else {
                helpers.addResult(results, 2,
                    'API Key is not restricted', 'global', key.name);
            }
        });

        return callback(null, results, source);
    }
};




