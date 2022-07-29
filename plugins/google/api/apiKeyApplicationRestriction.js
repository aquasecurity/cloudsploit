var helpers = require('../../../helpers/google');

module.exports = {
    title: 'API Key Application Restriction',
    category: 'API',
    domain: 'Identity and Access Management',
    description: 'Ensure there are no unrestricted API keys available within your GCP project.',
    more_info: 'To reduce the risk of attacks, Google Cloud API keys should be restricted only to trusted hosts, HTTP referrers, and Android/iOS mobile applications.',
    link: 'https://cloud.google.com/docs/authentication/api-keys#adding_application_restrictions',
    recommended_action: 'Ensure that Application restrictions are set for all Google Cloud API Keys.',
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
            let isRestricted = false;
            
            if (key.restrictions) {
                if (key.restrictions.browserKeyRestrictions && key.restrictions.browserKeyRestrictions.allowedReferrers
                    && key.restrictions.browserKeyRestrictions.allowedReferrers.length) {
                    isRestricted = key.restrictions.browserKeyRestrictions.allowedReferrers.every(referrer =>
                        referrer.match(/^(\*\.)?([\w-]+\.)+[\w-]+$/)
                    );
                } 
                if (key.restrictions.serverKeyRestrictions && key.restrictions.serverKeyRestrictions.allowedIps
                    && key.restrictions.serverKeyRestrictions.allowedIps.length) {
                    let allowedIps = key.restrictions.serverKeyRestrictions.allowedIps;
                    if (!(allowedIps.includes('0.0.0.0') || allowedIps.includes('0.0.0.0/0') || allowedIps.includes('::0'))) {
                        isRestricted = true;
                    }
                } 
            }
            if (isRestricted) {
                helpers.addResult(results, 0,
                    'API Key usage is restricted to trusted hosts, HTTP referrers, or applications', 'global', key.name);
            } else {
                helpers.addResult(results, 2,
                    'API Key usage is not restricted to trusted hosts, HTTP referrers, or applications', 'global', key.name);
            }
        });

        return callback(null, results, source);
    }
};




