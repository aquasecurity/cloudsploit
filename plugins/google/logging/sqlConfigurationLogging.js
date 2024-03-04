var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'SQL Configuration Logging',
    category: 'Logging',
    domain: 'Management and Governance',
    severity: 'Medium',
    description: 'Ensures that logging and log alerts exist for SQL configuration changes',
    more_info: 'Project Ownership is the highest level of privilege on a project, any changes in SQL configurations should be heavily monitored to prevent unauthorized changes.',
    link: 'https://cloud.google.com/logging/docs/logs-based-metrics/',
    recommended_action: 'Ensure that log metric and alert exist for SQL configuration changes.',
    apis: ['metrics:list', 'alertPolicies:list', 'sql:list'],
    compliance: {
        hipaa: 'HIPAA requires the logging of all activity ' +
            'including access and all actions taken.'
    },
    realtime_triggers: ['logging.MetricsServiceV2.CreateLogMetric', 'logging.MetricsServiceV2.DeleteLogMetric', 'cloudsql.instances.delete','cloudsql.instances.create'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.alertPolicies, function(region, rcb){
            let sqlInstances = helpers.addSource(
                cache, source, ['sql', 'list', region]);

            if (!sqlInstances) return rcb();

            if (sqlInstances.err || !sqlInstances.data) {
                helpers.addResult(results, 3, 'Unable to query SQL instances: ' + helpers.addError(sqlInstances), region, null, null, sqlInstances.err);
                return rcb();
            }

            if (!sqlInstances.data.length) {
                helpers.addResult(results, 0, 'No SQL instances found', region);
                return rcb();
            }
            var metrics = helpers.addSource(cache, source,
                ['metrics', 'list', region]);

            var alertPolicies = helpers.addSource(cache, source,
                ['alertPolicies', 'list', region]);

            if (!metrics || !alertPolicies) return rcb();

            if ((metrics.err && metrics.err.length > 0) || !metrics.data) {
                helpers.addResult(results, 3,
                    'Unable to query for log metrics: ' + helpers.addError(metrics), region, null, null, metrics.err);
                return rcb();
            }

            if ((alertPolicies.err && alertPolicies.err.length > 0) || !alertPolicies.data ) {
                helpers.addResult(results, 3,
                    'Unable to query for log alert policies: ' + helpers.addError(alertPolicies), region, null, null, alertPolicies.err);
                return rcb();
            }

            if (!metrics.data.length > 0) {
                helpers.addResult(results, 2, 'No log metrics found', region);
                return rcb();
            }

            if (!alertPolicies.data.length > 0) {
                helpers.addResult(results, 2, 'No log alert policies found', region);
                return rcb();
            }

            var metricExists = false;
            var metricName = '';

            var testMetrics = 'protoPayload.methodName="cloudsql.instances.update"';

            let disabled = false;
            for (let metric of metrics.data) {
                if (metric.filter) {
                    if (metricExists) break;

                    if (metric.filter.trim().indexOf(testMetrics) > -1) {
                        if (metric.disabled) disabled = true;
                        else {
                            disabled = false;
                            metricExists = true;
                            metricName = metric.metricDescriptor.type;
                        }
                    }
                }
            }

            if (disabled) {
                helpers.addResult(results, 2, 'Log metric for SQL configuration changes is disbled', region);
            } else if (metricExists && metricName.length) {
                var conditionFound = false;

                alertPolicies.data.forEach(alertPolicy => {
                    if (conditionFound) return;
                    if (alertPolicy.conditions &&
                        alertPolicy.conditions.length) {
                        alertPolicy.conditions.forEach(condition => {
                            if (conditionFound) return;
                            if (condition.conditionThreshold &&
                                condition.conditionThreshold.filter) {
                                var conditionFilter = condition.conditionThreshold.filter.split('"')[1];
                                if (conditionFilter === metricName) {
                                    conditionFound = true;
                                    helpers.addResult(results, 0, 'Log alert for SQL configuration changes is enabled', region, alertPolicy.name);
                                }
                            }
                        });
                    }
                });

                if (!conditionFound) {
                    helpers.addResult(results, 2, 'Log alert for SQL configuration changes not found', region);
                }
            } else {
                helpers.addResult(results, 2, 'Log metric for SQL configuration changes not found', region);
            }

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};
