var async = require('async');
var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'Legacy Metadata Endpoint Disabled',
    category: 'Compute',
    domain: 'Compute',
    severity: 'Medium',
    description: 'Ensure that compute instances are configured with Legacy MetaData service (IMDSv1) endpoints disabled.',
    more_info: 'For best security practices, it is recommended that the compute instances should be configured with legacy v1 endpoints (Instance Metadata Service v1) disabled, and use Instance Metadata Service v2 instead.',
    recommended_action: 'Ensure all compute instances are configured to use IMDSv2.',
    link: 'https://docs.oracle.com/en-us/iaas/Content/Compute/Tasks/gettingmetadata.htm#upgrading-v2',
    apis: ['instance:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings.govcloud);

        async.each(regions.instance, function(region, rcb){

            if (helpers.checkRegionSubscription(cache, source, results, region)) {

                var instances = helpers.addSource(cache, source,
                    ['instance', 'list', region]);

                if (!instances) return rcb();

                if (instances.err || !instances.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for instances: ' + helpers.addError(instances), region);
                    return rcb();
                }

                if (!instances.data.length) {
                    helpers.addResult(results, 0, 'No instances found', region);
                    return rcb();
                }

                instances.data.forEach(instance => {
                    if (instance.instanceOptions && instance.instanceOptions.areLegacyImdsEndpointsDisabled) {
                        helpers.addResult(results, 0, 'Instance has Legacy MetaData service (IMDSv1) endpoints disabled', region, instance.id);
                    } else {
                        helpers.addResult(results, 2, 'Instance does not have Legacy MetaData service (IMDSv1) endpoints disabled', region, instance.id);
                    }
                });
            }
            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};