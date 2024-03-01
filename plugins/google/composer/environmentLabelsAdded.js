var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Environment Labels Added',
    category: 'Cloud Composer',
    domain: 'Content Delivery',
    severity: 'Low',
    description: 'Ensures all Composer environments have labels added',
    more_info: 'Labels are a lightweight way to group resources together that are related to or associated with each other. It is a best practice to label cloud resources to better organize and gain visibility into their usage.',
    link: 'https://cloud.google.com/composer/docs/manage-environment-labels',
    recommended_action: 'Ensure labels are added to all cloud composer environments',
    apis: ['composer:environments'],
    realtime_triggers: ['orchestration.airflow.service.Environments.CreateEnviroments', 'orchestration.airflow.service.Environments.UpdateEnvironment', 'orchestration.airflow.service.Environments.DeleteEnvironment'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        let projects = helpers.addSource(cache, source,
            ['projects','get', 'global']);

        if (!projects || projects.err || !projects.data || !projects.data.length) {
            helpers.addResult(results, 3,
                'Unable to query for projects: ' + helpers.addError(projects), 'global', null, null, (projects) ? projects.err : null);
            return callback(null, results, source);
        }

        async.each(regions.composer, function(region, rcb){
            let environments = helpers.addSource(cache, source,
                ['composer', 'environments', region]);

            if (!environments) return rcb();

            if (environments.err || !environments.data) {
                helpers.addResult(results, 3, 'Unable to query Composer environments', region, null, null, environments.err);
                return rcb();
            }

            if (!environments.data.length) {
                helpers.addResult(results, 0, 'No Composer environments found', region);
                return rcb();
            }

            environments.data.forEach(environment => {
                if (environment.labels &&
                    Object.keys(environment.labels).length) {
                    helpers.addResult(results, 0,
                        `${Object.keys(environment.labels).length} labels found for composer environment`, region, environment.name);
                } else {
                    helpers.addResult(results, 2,
                        'Composer environment does not have any labels added', region, environment.name);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};