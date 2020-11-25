var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'VPC Multiple Subnets',
    category: 'EC2',
    description: 'Ensures that VPCs have multiple subnets to provide a layered architecture',
    more_info: 'VPCs should be designed to have separate public and private subnets, ideally across availability zones, enabling a DMZ-style architecture.',
    link: 'https://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Subnets.html#SubnetSecurity',
    recommended_action: 'Create at least two subnets in each VPC, utilizing one for public traffic and the other for private traffic.',
    apis: ['EC2:describeVpcs', 'EC2:describeSubnets'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.ec2, function(region, rcb){
            var describeVpcs = helpers.addSource(cache, source,
                ['ec2', 'describeVpcs', region]);

            if (!describeVpcs) return rcb();

            if (describeVpcs.err || !describeVpcs.data) {
                helpers.addResult(results, 3,
                    'Unable to query for VPCs: ' + helpers.addError(describeVpcs), region);
                return rcb();
            }

            if (!describeVpcs.data.length) {
                helpers.addResult(results, 0, 'No VPCs found', region);
                return rcb();
            }

            if (describeVpcs.data.length > 1) {
                helpers.addResult(results, 0,
                    'Multiple (' + describeVpcs.data.length + ') VPCs are used.', region);
                return rcb();
            }

            var vpcId = describeVpcs.data[0].VpcId;

            if (!vpcId) {
                helpers.addResult(results, 3, 'Unable to query for subnets for VPC.', region);
                return rcb();
            }

            var describeSubnets = helpers.addSource(cache, source,
                ['ec2', 'describeSubnets', region, vpcId]);

            if (!describeSubnets || describeSubnets.err || !describeSubnets.data || !describeSubnets.data.Subnets) {
                helpers.addResult(results, 3,
                    'Unable to query for subnets in VPC: ' + helpers.addError(describeSubnets), region, vpcId);
                return rcb();
            }

            if (describeSubnets.data.Subnets.length > 1) {
                helpers.addResult(results, 0,
                    'There are ' + describeSubnets.data.Subnets.length + ' subnets used in one VPC.',
                    region, vpcId);
            } else if (describeSubnets.data.Subnets.length === 1) {
                helpers.addResult(results, 2,
                    'Only one subnet (' + describeSubnets.data.Subnets[0].SubnetId + ') in one VPC is used.',
                    region, vpcId);
            } else {
                helpers.addResult(results, 0,
                    'The VPC does not contain any subnets',
                    region, vpcId);
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};