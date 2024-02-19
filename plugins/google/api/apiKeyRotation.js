var helpers = require('../../../helpers/google');

module.exports = {
    title: 'API Key Rotation',
    category: 'API',
    domain: 'Identity and Access Management',
    severity: 'Medium',
    description: 'Ensure that your Google Cloud API Keys are periodically regenerated.',
    more_info: 'Make sure that your Google API Keys are regenerated regularly to avoid data leaks and unauthorized access through outdated API Keys.',
    link: 'https://cloud.google.com/docs/authentication/api-keys',
    recommended_action: 'Ensure that all your Google Cloud API keys are regenerated (rotated) after a specific period.',
    apis: ['apiKeys:list'],
    settings: {
        api_keys_rotation_warn_interval: {
            name: 'API Keys Rotation Warn Interval',
            description: 'Return a warning result when api keys exceed this number of days without being rotated',
            regex: '^[1-9]{1}[0-9]{0,3}$',
            default: '45'
        },
        api_keys_rotation_fail_interval: {
            name: 'API Keys Rotation Fail Interval',
            description: 'Return a failing result when api keys exceed this number of days without being rotated',
            regex: '^[1-9]{1}[0-9]{0,3}$',
            default: '90'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var apiKeyRotationFailInterval = parseInt(settings.api_keys_rotation_fail_interval || this.settings.api_keys_rotation_fail_interval.default);
        var apiKeyRotationWarnInterval = parseInt(settings.api_keys_rotation_warn_interval || this.settings.api_keys_rotation_warn_interval.default);

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
            var diffInDays = helpers.daysBetween(key.createTime, new Date());

            if (diffInDays > apiKeyRotationFailInterval) {
                helpers.addResult(results, 2,
                    `API Key was last rotated ${diffInDays} days ago which is greater than ${apiKeyRotationFailInterval}`, 'global', key.name);
            } else if (diffInDays > apiKeyRotationWarnInterval) {
                helpers.addResult(results, 1,
                    `API Key was last rotated ${diffInDays} days ago which is greater than ${apiKeyRotationWarnInterval}`, 'global', key.name);
            } else {
                helpers.addResult(results, 0,
                    `API Key was last rotated ${diffInDays} days ago`, 'global', key.name);
            }
        });

        return callback(null, results, source);
    }
};




