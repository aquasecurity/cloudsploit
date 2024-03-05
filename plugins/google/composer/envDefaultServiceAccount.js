var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Environment Default Service Account',
    category: 'Cloud Composer',
    domain: 'Content Delivery',
    severity: 'Low',
    description: 'Ensure Composer environment is not using the default compute engine service account',
    more_info: 'The Composer environment node VMs uses a service account to deploy different pods like Airflow workers and schedulers.By default it uses the compute engine service account which has the editor role on the project. This allows the VM node to have read and write permissions on most of the GCP services. To prevent privilege escalation, it is recommended to create a new service account with limited permissions for your VM instead of using the default one.',
    link: 'https://cloud.google.com/compute/docs/access/service-accounts',
    recommended_action: 'Make sure that composer environments are not using default service account',
    apis: ['composer:environments', 'projects:get'],
    realtime_triggers: ['orchestration.airflow.service.Environments.CreateEnviroments', 'orchestration.airflow.service.Environments.DeleteEnvironment'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        let projects = helpers.addSource(cache, source,
            ['projects','get', 'global']);

        if (!projects) return callback(null, results, source);

        if (projects.err || !projects.data) {
            helpers.addResult(results, 3,
                'Unable to query for projects: ' + helpers.addError(projects), 'global');
            return callback(null, results, source);
        }

        if (!projects.data.length) {
            helpers.addResult(results, 0, 'No projects found', 'global');
            return callback(null, results, source);
        }

        var defaultServiceAccount = projects.data[0].defaultServiceAccount;

        if (!defaultServiceAccount) return callback(null, results, source);

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
                if (environment.config && environment.config.nodeConfig &&
                    environment.config.nodeConfig.serviceAccount && environment.config.nodeConfig.serviceAccount === defaultServiceAccount) {
                    helpers.addResult(results, 2,
                        'Composer environment is using default service account', region, environment.name);
                } else {
                    helpers.addResult(results, 0,
                        'Composer environment is not using default service account', region, environment.name);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};