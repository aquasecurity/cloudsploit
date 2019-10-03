var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Flow Logs Enabled',
    category: 'VPC Network',
    description: 'Ensures VPC flow logs are enabled for traffic logging',
    more_info: 'VPC flow logs record all traffic flowing in to and out of a VPC. These logs are critical for auditing and review after security incidents.',
    link: 'https://cloud.google.com/vpc/docs/using-flow-logs',
    recommended_action: 'Enable VPC flow logs for each VPC Subnetwork',
    apis: ['subnetworks:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.subnetworks, function(region, rcb){
            let subnetworks = helpers.addSource(
                cache, source, ['subnetworks', 'list', region]);

            if (!subnetworks) return rcb();

            if (subnetworks.err || !subnetworks.data) {
                helpers.addResult(results, 3, 'Unable to query subnetworks: ' + helpers.addError(subnetworks), region);
                return rcb();
            };

            if (!subnetworks.data.length) {
                helpers.addResult(results, 0, 'No subnetworks present', region);
                return rcb();
            };
            
            var badSubnets = [];
            subnetworks.data.forEach(subnet => {
                if (!subnet.enableFlowLogs) {
                    badSubnets.push(subnet.id);
                };
            });

            if (badSubnets.length) {
                var badSubnetStr = badSubnets.join(', ');
                helpers.addResult(results, 2,
                     `The following Subnets do not have Flow Logs enabled: ${badSubnetStr}`, region);
            } else {
                helpers.addResult(results, 0, 'All Subnets in the Region have Flow Logs enabled', region);
            };

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
}