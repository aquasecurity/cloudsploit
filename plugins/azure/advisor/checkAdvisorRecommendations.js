var async = require('async');
var helpers = require('../../../helpers/azure');

module.exports = {
    title: 'Active Advisor Recommendations',
    category: 'Advisor',
    domain: 'Application Integration',
    severity: 'Medium',
    description: 'Ensure that all Microsoft Azure Advisor recommendations found are implemented to optimize your cloud deployments, increase security, and reduce costs.',
    more_info: 'Advisor service analyzes your Azure cloud configurations and resource usage telemetry to provide personalized and actionable recommendations that can help you optimize your cloud resources for security, reliability and high availability, operational excellence, performance efficiency, and cost.',
    recommended_action: 'Implement all Microsoft Azure Advisor recommendations.',
    link: 'https://learn.microsoft.com/en-us/azure/advisor/advisor-get-started',
    apis: ['advisor:recommendationsList'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var locations = helpers.locations(settings.govcloud);

        async.each(locations.advisor, function(location, rcb) {
            const recommendationList = helpers.addSource(cache, source,
                ['advisor', 'recommendationsList', location]);

            if (!recommendationList) return rcb();

            if (recommendationList.err || !recommendationList.data) {
                helpers.addResult(results, 3, 'Unable to query for Advisor Recommendations: ' + helpers.addError(recommendationList), location);
                return rcb();
            }

            if (!recommendationList.data.length) {
                helpers.addResult(results, 0, 'No Advisor Recommendations found', location);
                return rcb();
            } else {
                helpers.addResult(results, 2, 'Active Advisor Recommendations found', location);
            }

            rcb();
        }, function() {
            callback(null, results, source);
        });
    }
};
