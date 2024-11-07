var async = require('async');
var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'Flow Logs Enabled',
    category: 'Networking',
    domain: 'Management and Governance',
    severity: 'Medium',
    description: 'Ensures VCN flow logs are enabled for traffic logging.',
    more_info: 'VCN flow logs allow you to monitor traffic flowing within your virtual network and can help in detecting anomalous traffic.',
    link: 'https://docs.oracle.com/en-us/iaas/Content/Network/Concepts/vcn_flow_logs.htm',
    recommended_action: 'Enable VCN flow logs for each VCN subnet.',
    apis: ['vcn:list', 'subnet:list', 'logGroup:list', 'log:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings.govcloud);

        async.each(regions.subnet, function(region, rcb){

            if (helpers.checkRegionSubscription(cache, source, results, region)) {

                var subnets = helpers.addSource(cache, source,
                    ['subnet', 'list', region]);

                if (!subnets) return rcb();

                if (subnets.err || !subnets.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for subnets: ' + helpers.addError(subnets), region);
                    return rcb();
                }

                if (!subnets.data.length) {
                    helpers.addResult(results, 0, 'No subnets found', region);
                    return rcb();
                }

                var logs = helpers.addSource(cache, source,
                    ['log', 'list', region]);
                
                subnets.data.forEach(subnet  => {                    
                    let subnetFlowLog = null;

                    if (logs && !logs.err && logs.data && logs.data.length) {
                        subnetFlowLog = logs.data.find(log => log.isEnabled && log.configuration 
                            && Object.keys(log.configuration).length && log.configuration.source 
                            && Object.keys(log.configuration.source).length && log.configuration.source.service === 'flowlogs' 
                            && log.configuration.source.resource === subnet.id);
                    }

                    if (subnetFlowLog) {
                        helpers.addResult(results, 0, 'The subnet has flow logs enabled', region, subnet.id);
                    } else {
                        helpers.addResult(results, 2, 'The subnet does not have flow logs enabled', region, subnet.id);
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