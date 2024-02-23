var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Project API Keys',
    category: 'API',
    domain: 'Identity and Access Management',
    severity: 'Low',
    description: 'Ensure there are no API keys created within GCP project.',
    more_info: 'API Keys are insecure because they can be viewed publicly, such as from within a browser, or they can be accessed on a device where the key resides. To avoid the security risk in using API keys, it is recommended to use standard authentication flow instead.',
    link: 'https://cloud.google.com/docs/authentication/api-keys',
    recommended_action: 'Ensure that there are no API Keys within the project.',
    apis: ['apiKeys:list'],

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

        let project = projects.data[0].name;

        let apiKeys = helpers.addSource(cache, source,
            ['apiKeys', 'list', 'global']);
    
        if (!apiKeys) return callback(null, results, source);

        if (apiKeys.err || !apiKeys.data) {
            helpers.addResult(results, 3, 'Unable to query API Keys for project', 'global', null, null, apiKeys.err);
            return callback(null, results, source);
        }

        if (!apiKeys.data.length) {
            helpers.addResult(results, 0,
                'API Keys do not exist in the project', 'global', project);
        } else {
            helpers.addResult(results, 2,
                'API Keys exist in the project', 'global', project);
        }

        return callback(null, results, source);
    }
};




