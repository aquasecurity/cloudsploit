var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Audit Configuration Logging',
    category: 'Logging',
    description: 'Ensures that logging and log alerts exist for audit configuration changes.',
    more_info: 'Project Ownership is the highest level of privilege on a project, any changes in audit configuration should be heavily monitored to prevent unauthorized changes.',
    link: 'https://cloud.google.com/logging/docs/logs-based-metrics/',
    recommended_action: 'Ensure that log alerts exist for audit configuration changes.',
    apis: ['metrics:list', 'alertPolicies:list'],
    compliance: {
        hipaa: 'HIPAA has clearly defined audit requirements for environments ' +
            'containing sensitive data.',
        pci: 'PCI has a strict requirement to log all account activity ' +
             'within environments containing cardholder data.',
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.alertPolicies, function(region, rcb){
            var metrics = helpers.addSource(cache, source,
                ['metrics', 'list', region]);

            var alertPolicies = helpers.addSource(cache, source,
                ['alertPolicies', 'list', region]);

            if (!metrics || !alertPolicies) return rcb();

            if ((metrics.err && metrics.err.length > 0) || !metrics.data) {
                helpers.addResult(results, 3,
                    'Unable to query for log metrics: ' + helpers.addError(metrics), region);
                return rcb();
            }

            if ((alertPolicies.err && alertPolicies.err.length > 0) || !alertPolicies.data ) {
                helpers.addResult(results, 3,
                    'Unable to query for log alert policies: ' + helpers.addError(alertPolicies), region);
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
            var missingMetricStr;

            var testMetrics = 'protoPayload.methodName="SetIamPolicy" AND protoPayload.serviceData.policyDelta.auditConfigDeltas:*';


            metrics.data.forEach(metric => {
                if (metric.filter) {
                    if (metricExists) return;

                    if (metric.filter === testMetrics) {
                        metricExists = true;
                        metricName = metric.metricDescriptor.type;
                    } else {
                       return
                    }
                }
            });

            if (metricExists && metricName.length) {
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
                                    helpers.addResult(results, 0, 'Log alert for audit configuration changes is enabled', region, alertPolicy.name);
                                }
                            }
                        })
                    }
                });

                if (!conditionFound) {
                    helpers.addResult(results, 2, 'Log alert for audit configuration changes not found', region);
                }
            } else {
                helpers.addResult(results, 2, 'Log metric for audit configuration changes not found', region);
            }

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};




