var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Web Server Public Access',
    category: 'MWAA',
    description: 'Ensures web access to the Apache Airflow UI in your MWAA environment is not public.',
    more_info: 'To restrict access to the Apache Airflow UI, environment should be configured to be accessible only from within the VPC selected.',
    link: 'https://docs.aws.amazon.com/mwaa/latest/userguide/vpc-create.html',
    recommended_action: 'Modify Amazon MWAA environments to set web server access mode to be private only',
    apis: ['MWAA:listEnvironments', 'MWAA:getEnvironment', 'STS:getCallerIdentity'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var defaultRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', defaultRegion, 'data']);

        async.each(regions.mwaa, function(region, rcb){
            var listEnvironments = helpers.addSource(cache, source,
                ['mwaa', 'listEnvironments', region]);

            if (!listEnvironments) return rcb();

            if (listEnvironments.err || !listEnvironments.data) {
                helpers.addResult(results, 3,
                    `Unable to query for Airflow environments: ${helpers.addError(listEnvironments)}`, region);
                return rcb();
            }

            if (!listEnvironments.data.length) {
                helpers.addResult(results, 0, 'No Airflow environments found', region);
                return rcb();
            }

            async.each(listEnvironments.data, function(airflowEnv, cb){
                var resource = `arn:${awsOrGov}:airflow:${region}:${accountId}:environment/${airflowEnv}`;

                var getEnvironment = helpers.addSource(cache, source,
                    ['mwaa', 'getEnvironment', region, airflowEnv]);

                if (!getEnvironment || getEnvironment.err || !getEnvironment.data || !getEnvironment.data.Environment) {
                    helpers.addResult(results, 3,
                        `Unable to get Airflow environment: ${helpers.addError(getEnvironment)}`, region, resource);
                    return cb();
                }

                if (getEnvironment.data.Environment.WebserverAccessMode &&
                    getEnvironment.data.Environment.WebserverAccessMode.toUpperCase() === 'PRIVATE_ONLY') {
                    helpers.addResult(results, 0,
                        'Apache Airflow UI can only be accessible from within the VPC',
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'Apache Airflow UI can be accessed over the internet',
                        region, resource);
                }
                
                cb();
            }, function(){
                rcb();
            });
        }, function(){
            callback(null, results, source);
        });
    }
};
