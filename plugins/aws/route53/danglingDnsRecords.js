var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'AWS Route53 Dangling DNS Records',
    category: 'Route53',
    description: 'Ensures that AWS Route53 DNS records are not pointing to invalid/deleted EIPs.',
    more_info: 'AWS Route53 DNS records should not point to invalid/deleted EIPs to prevent malicious activities.',
    link: 'https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/routing-to-aws-resources.html',
    recommended_action: 'Delete invalid/dangling AWS Route53 DNS records',
    apis: ['Route53:listHostedZones', 'Route53:listResourceRecordSets', 'EC2:describeAddresses'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var region = helpers.defaultRegion(settings);

        var listHostedZones = helpers.addSource(cache, source,
            ['route53', 'listHostedZones', region]);

        if (!listHostedZones) return callback(null, results, source);
        
        if (listHostedZones.err || !listHostedZones.data) {
            helpers.addResult(results, 3,
                `Unable to query for hosted zones: ${helpers.addError(listHostedZones)}`,
                region);
            return callback(null, results, source);
        }

        if (!listHostedZones.data.length) {
            helpers.addResult(results, 0, 'No Route53 Hosted Zones found', region);
            return callback(null, results, source);
        }

        var addresses = [];
        async.each(helpers.regions(settings).ec2, function(region, rcb) {
            var describeAddresses = helpers.addSource(cache, source,
                ['ec2', 'describeAddresses', region]);
    
            if (!describeAddresses) return rcb();

            if (describeAddresses.err || !describeAddresses.data) {
                helpers.addResult(results, 3,
                    `Unable to query for elastic IP addresses: ${helpers.addError(describeAddresses)}`,
                    region);
                return rcb();
            }

            if (describeAddresses.data.length) {
                describeAddresses.data.forEach(address => {
                    if (address.PublicIp) {
                        addresses.push(address.PublicIp);
                    }
                });
            }

            rcb();
        });

        async.each(listHostedZones.data, function(zone, cb){
            var resource = `arn:aws:route53:::${zone.Id}`;

            var listResourceRecordSets = helpers.addSource(cache, source,
                ['route53', 'listResourceRecordSets', region, zone.Id]);

            if (!listResourceRecordSets || listResourceRecordSets.err || !listResourceRecordSets.data) {
                helpers.addResult(results, 3,
                    `Unable to query for resource record sets: ${helpers.addError(listResourceRecordSets)}`,
                    region, resource);
                return cb();
            }

            if (!listResourceRecordSets.data.ResourceRecordSets || !listResourceRecordSets.data.ResourceRecordSets.length) {
                helpers.addResult(results, 0,
                    'No resource record sets found',
                    region, resource);
                return cb();
            }

            var danglingDnsRecords = [];
            listResourceRecordSets.data.ResourceRecordSets.forEach(recordSet => {
                if (recordSet.Type && recordSet.Type === 'A' && recordSet.ResourceRecords && recordSet.ResourceRecords.length) {
                    recordSet.ResourceRecords.forEach(record => {
                        if (record.Value && !addresses.includes(record.Value)) {
                            danglingDnsRecords.push(record.Value);
                        }
                    });
                }
            });

            if (!danglingDnsRecords.length) {
                helpers.addResult(results, 0,
                    `Hosted Zone "${zone.Name}" does not have any dangling DNS records`,
                    region, resource);
            } else {
                helpers.addResult(results, 2,
                    `Hosted Zone "${zone.Name}" has these dangling DNS records: ${danglingDnsRecords.join(', ')}`,
                    region, resource);
            }

            cb();
        }, function(){
            callback(null, results, source);
        });
    }
};
