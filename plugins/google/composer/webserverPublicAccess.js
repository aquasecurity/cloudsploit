var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Airflow Web Server Public Access',
    category: 'Cloud Composer',
    domain: 'Content Delivery',
    severity: 'Medium',
    description: 'Ensure Composer Airflow web server is not open to the world',
    more_info: 'Allowing access from all IP addresses on the Internet to Composer Environments is risky as it can lead to Brute Force or DoS attacks. As a security best practice, only allow access from required IP ranges.',
    link: 'https://cloud.google.com/composer/docs/concepts/private-ip',
    recommended_action: 'Ensure that all composer environments have private airflow web servers',
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
                if (environment.config && environment.config.webServerNetworkAccessControl 
                    && environment.config.webServerNetworkAccessControl.allowedIpRanges 
                    && !(environment.config.webServerNetworkAccessControl.allowedIpRanges.find(
                        range => ['0.0.0.0/0', '::0/0'].includes(range.value)
                    ))) {
                    helpers.addResult(results, 0,
                        'Composer Airflow Web Server does not allow public access', region, environment.name);
                } else {
                    helpers.addResult(results, 2,
                        'Composer Airflow Web Server allows public access', region, environment.name);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};