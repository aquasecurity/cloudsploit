var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'Cloud Guard Enabled',
    category: 'Cloud Guard',
    domain: 'Management and Governance',
    description: 'Ensure Cloud Guard is enabled in the root compartment of the tenancy.',
    more_info: 'Cloud Guard detects misconfigured resources and insecure activity within a tenancy and provides security administrators with the visibility to resolve these issues. Upon detection, Cloud Guard can suggest, assist, or take corrective actions to mitigate these issues.',
    recommended_action: 'Cloud Guard should be enabled in the root compartment of your tenancy.',
    link: 'https://docs.oracle.com/en-us/iaas/cloud-guard/using/index.htm',
    apis: ['cloudguardConfiguration:get'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var region = helpers.objectFirstKey(cache['regionSubscription']['list']);

        if (helpers.checkRegionSubscription(cache, source, results, region)) {
           
            var config = helpers.addSource(cache, source,
                ['cloudguardConfiguration', 'get', region]);

            if (!config) return callback(null, results, source);

            if (config.err) {
                helpers.addResult(results, 3,
                    'Unable to query for cloud guard configuration: ' + helpers.addError(config), region);
                return callback(null, results, source);
            }
            if (config.data && Object.keys(config.data).length && config.data.status && config.data.status === 'ENABLED') {
                helpers.addResult(results, 0,
                    'Cloud Guard is enabled in the root compartment of the tenancy.', region);
            } else {
                helpers.addResult(results, 2,
                    'Cloud Guard is not enabled in the root compartment of the tenancy.', region);
            }
        }
        callback(null, results, source);
    }
};