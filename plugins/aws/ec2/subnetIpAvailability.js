var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Subnet IP Availability',
    category: 'EC2',
    description: 'Determine if a subnet is at risk of running out of IP addresses',
    more_info: 'Subnets have finite IP addresses. Running out of IP addresses could prevent resources from launching.',
    recommended_action: 'Add a new subnet with larger CIDR block and migrate resources.',
    link: 'http://docs.aws.amazon.com/AmazonVPC/latest/UserGuide/VPC_Subnets.html',
    apis: ['EC2:describeSubnets', 'STS:getCallerIdentity'],
    settings: {
        subnet_ip_availability_percentage_fail: {
            name: 'Subnet IP Availability Percentage Fail',
            description: 'Return a failing result when consumed subnet IPs equals or exceeds this percentage',
            regex: '^(100|[1-9][0-9]?)$',
            default: 90
        },
        subnet_ip_availability_percentage_warn: {
            name: 'Subnet IP Availability Percentage Warn',
            description: 'Return a warning result when consumed subnet IPs equals or exceeds this percentage',
            regex: '^(100|[1-9][0-9]?)$',
            default: 75
        }
    },

    run: function(cache, settings, callback) {
        var config = {
            subnet_ip_availability_percentage_fail: settings.subnet_ip_availability_percentage_fail || this.settings.subnet_ip_availability_percentage_fail.default,
            subnet_ip_availability_percentage_warn: settings.subnet_ip_availability_percentage_warn || this.settings.subnet_ip_availability_percentage_warn.default
        };

        var custom = helpers.isCustom(settings, this.settings);

        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        async.each(regions.ec2, function(region, rcb){
            var describeSubnets = helpers.addSource(cache, source,
                ['ec2', 'describeSubnets', region]);

            if (!describeSubnets) return rcb();

            if (describeSubnets.err || !describeSubnets.data) {
                helpers.addResult(results, 3,
                    'Unable to query for subnets: ' + helpers.addError(describeSubnets), region);
                return rcb();
            }

            if (!describeSubnets.data.length) {
                helpers.addResult(results, 0, 'No subnets found', region);
                return rcb();
            }

            for(var i in describeSubnets.data){
                var subnetSize = helpers.cidrSize(describeSubnets.data[i].CidrBlock);
                var consumedIPs = subnetSize - describeSubnets.data[i].AvailableIpAddressCount;
                var percentageConsumed = Math.ceil((consumedIPs / subnetSize) * 100);
                var subnetArn = 'arn:aws:ec2:' + region + ':' + accountId + ':subnet/' + describeSubnets.data[i].SubnetId;

                var returnMsg = 'Subnet ' + describeSubnets.data[i].SubnetId
                            + ' is using ' + consumedIPs + ' of '
                            + subnetSize + ' (' + percentageConsumed + '%) available IPs.';

                if (percentageConsumed >= config.subnet_ip_availability_percentage_fail) {
                    helpers.addResult(results, 2, returnMsg, region, subnetArn, custom);
                } else if (percentageConsumed >= config.subnet_ip_availability_percentage_warn) {
                    helpers.addResult(results, 1, returnMsg, region, subnetArn, custom);
                } else {
                    helpers.addResult(results, 0, returnMsg, region, subnetArn, custom);
                }
            }
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};