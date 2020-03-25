var async = require('async');
var helpers = require('../../../helpers/oracle');

module.exports = {
    title: 'VCN Multiple Subnets',
    category: 'Networking',
    description: 'Ensures that VCNs have multiple networks to provide a layered architecture',
    more_info: 'A single network within a VCN increases the risk of a broader blast radius in the event of a compromise.',
    link: 'https://docs.cloud.oracle.com/iaas/Content/Network/Tasks/managingVCNs.htm',
    recommended_action: 'Create multiple networks/subnets in each VCN and change the architecture to take advantage of public and private tiers.',
    apis: ['vcn:list', 'subnet:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.vcn, function(region, rcb){
            if (helpers.checkRegionSubscription(cache, source, results, region)) {

                var vcns = helpers.addSource(cache, source,
                    ['vcn', 'list', region]);

                if (!vcns) return rcb();

                if (vcns.err || !vcns.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for VCNs: ' + helpers.addError(vcns), region);
                    return rcb();
                }

                if (!vcns.data.length) {
                    helpers.addResult(results, 0, 'No VCNs found', region);
                    return rcb();
                }

                if (vcns.data.length > 1) {
                    helpers.addResult(results, 0,
                        'Multiple (' + vcns.data.length + ') VCNs are used.', region);
                    return rcb();
                }

                // Looks like we have only one VCN
                var vcnId = vcns.data[0].id;

                if (!vcnId) {
                    helpers.addResult(results, 3, 'Unable to query for subnets for VCN.', region);
                    return rcb();
                }

                var subnets = helpers.addSource(cache, source,
                    ['subnet', 'list', region]);

                
                if (!subnets || (subnets.err && subnets.err.length)|| !subnets.data) {
                    helpers.addResult(results, 3,
                        'Unable to query for subnets: ' + helpers.addError(subnets), region);
                    return rcb();
                }

                var vcnSubnets = subnets.data.filter(subnet => {
                    if (subnet.vcnId) return subnet.vcnId === vcnId;
                });

                if (vcnSubnets.length > 1) {
                    helpers.addResult(results, 0,
                        'There are ' + vcnSubnets.length + ' different subnets used in one VCN.',region, vcnId);
                } else if (vcnSubnets.length === 1) {
                    helpers.addResult(results, 2,
                        'Only one subnet (' + vcnSubnets[0].id + ') in one VCN is used.', region, vcnId);
                } else {
                    helpers.addResult(results, 0,
                        'The VCN does not have any subnets', region, vcnId);
                }
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
