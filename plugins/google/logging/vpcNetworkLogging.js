var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'VPC Network Logging',
    category: 'Logging',
    description: 'Ensures that logging and log alerts exist for VPC network changes',
    more_info: 'Project Ownership is the highest level of privilege on a project, any changes in VPC network should be heavily monitored to prevent unauthorized changes.',
    link: 'https://cloud.google.com/logging/docs/logs-based-metrics/',
    recommended_action: 'Ensure that log alerts exist for VPC network changes.',
    apis: ['metrics:list', 'alertPolicies:list'],
    compliance: {
        pci: 'PCI requires tracking and monitoring of all access to environments ' +
            'in which cardholder data is present. VPC network logging ' +
            'helps audit all network changes.',
        hipaa: 'HIPAA requires the logging of all activity ' +
            'including access and all actions taken.'
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

            var testMetrics = [
                'resource.type=gce_network AND jsonPayload.event_subtype="compute.networks.insert"',
                'jsonPayload.event_subtype="compute.networks.patch"',
                'jsonPayload.event_subtype="compute.networks.delete"',
                'jsonPayload.event_subtype="compute.networks.removePeering"',
                'jsonPayload.event_subtype="compute.networks.addPeering"'
            ];

            metrics.data.forEach(metric => {
                if (metric.filter) {
                    if (metricExists) return;
                    var checkMetrics = metric.filter.trim().split(' OR ');
                    var missingMetrics = [];

                    testMetrics.forEach(testMetric => {
                        if (checkMetrics.indexOf(testMetric) === -1) {
                            missingMetrics.push(testMetric);
                        }
                    });

                    if (missingMetrics.length > 2) {
                        return;
                    } else if (missingMetrics.length > 0) {
                        metricExists = true;
                        missingMetricStr = missingMetrics.join(', ');
                    } else if (missingMetrics.length === 0) {
                        metricExists = true;
                        metricName = metric.metricDescriptor.type;
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
                                    helpers.addResult(results, 0, 'Log alert for VPC network changes is enabled', region, alertPolicy.name);
                                }
                            }
                        })
                    }
                });

                if (!conditionFound) {
                    helpers.addResult(results, 2, 'Log alert for VPC network changes not found', region);
                }
            } else {
                helpers.addResult(results, 2, 'Log metric for VPC network changes not found', region);
            }

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};




