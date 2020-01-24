var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Flow Logs Enabled',
    category: 'VPC Network',
    description: 'Ensures VPC flow logs are enabled for traffic logging',
    more_info: 'VPC flow logs record all traffic flowing in to and out of a VPC. These logs are critical for auditing and review after security incidents.',
    link: 'https://cloud.google.com/vpc/docs/using-flow-logs',
    recommended_action: 'Enable VPC flow logs for each VPC subnet',
    apis: ['subnetworks:list'],
    compliance: {
        hipaa: 'VPC Flow Logs provide a detailed traffic log of a VPC network ' +
            'containing HIPAA data. Flow Logs should be enabled to satisfy ' +
            'the audit controls of the HIPAA framework.',
        pci: 'PCI requires logging of all network access to environments containing ' +
            'cardholder data. Enable VPC flow logs to log these network requests.'
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.subnetworks, function(region, rcb){
            let subnetworks = helpers.addSource(cache, source,
                ['subnetworks', 'list', region]);

            if (!subnetworks) return rcb();

            if (subnetworks.err || !subnetworks.data) {
                helpers.addResult(results, 3, 'Unable to query subnets: ' + helpers.addError(subnetworks), region);
                return rcb();
            }

            if (!subnetworks.data.length) {
                helpers.addResult(results, 0, 'No subnets found', region);
                return rcb();
            }
            
            subnetworks.data.forEach(subnet => {
                if (subnet.creationTimestamp &&
                    !subnet.enableFlowLogs) {
                    helpers.addResult(results, 2,
                        'The subnet does not have flow logs enabled', region, subnet.id);
                } else if (subnet.creationTimestamp) {
                    helpers.addResult(results, 0, 'The subnet has flow logs enabled', region, subnet.id);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};