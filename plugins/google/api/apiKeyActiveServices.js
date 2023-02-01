var helpers = require('../../../helpers/google');

module.exports = {
    title: 'API Key Active Services Only',
    category: 'API',
    domain: 'Identity and Access Management',
    description: 'Ensure API Keys only exist for active services.',
    more_info: 'API Keys should only be used for services in cases where other authentication methods are unavailable. Keys are insecure because they can be viewed publicly, such as from within a browser, or they can be accessed on a device where the key resides. It is recommended to use standard authentication flow to avoid risks associated with API Keys.',
    link: 'https://cloud.google.com/docs/authentication/api-keys',
    recommended_action: 'Ensure that API Keys only exist for active services.',
    apis: ['projects:getWithNumber', 'apiKeys:list', 'services:listEnabled'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};

        let projects =  helpers.addSource(cache, source, 
            ['projects', 'getWithNumber', 'global']);

        
        if (!projects || projects.err || !projects.data || !projects.data.length) {
            helpers.addResult(results, 3,
                'Unable to query for projects: ' + helpers.addError(projects), 'global', null, null, (projects) ? projects.err : null);
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

        let services = helpers.addSource(cache, source, 
            ['services', 'listEnabled', 'global']);

        if (!services || services.err || !services.data) {
            helpers.addResult(results, 3,
                'Unable to query services for project: ' + helpers.addError(services), 'global', null, null, (services) ? services.err : null);
            return callback(null, results, source);
        }

        apiKeys.data.forEach(key => {  
            if (services.data.length && key.restrictions && key.restrictions.apiTargets
                && key.restrictions.apiTargets.length
                && key.restrictions.apiTargets.every(
                    target => target.service && services.data.find(service => service.name.includes(target.service)))) {
                helpers.addResult(results, 0,
                    'API Key usage is restricted to active services', 'global', key.name);
            } else {
                helpers.addResult(results, 2,
                    'API Key usage is not restricted to active services', 'global', key.name);
            }
        });

        return callback(null, results, source);
    }
};




