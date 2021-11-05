var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Sender Policy Framework In Use',
    category: 'Route53',
    domain: 'Content Delivery',
    description: 'Ensure that Sender Policy Framework (SPF) is used to stop spammers from spoofing your AWS Route 53 domain.',
    more_info: 'The Sender Policy Framework enables AWS Route 53 registered domain to publicly state the mail servers that are authorized to send emails on its behalf.',
    link: 'https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/rrsets-working-with.html',
    recommended_action: 'Updated the domain records to have SPF.',
    apis: ['Route53:listHostedZones', 'Route53:listResourceRecordSets'],

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

        async.each(listHostedZones.data, function(zone, cb){
            if (!zone.Id) return cb();

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

            var spfDisabledDnsRecords = [];
            listResourceRecordSets.data.ResourceRecordSets.forEach(recordSet => {
                if (recordSet.Type && recordSet.Type.toUpperCase() === 'TXT' && recordSet.ResourceRecords && recordSet.ResourceRecords.length) {
                    recordSet.ResourceRecords.forEach(record => {
                        if (record.Value && !record.Value.includes('v=spf1') && !spfDisabledDnsRecords.includes(recordSet.Name)) {
                            spfDisabledDnsRecords.push(recordSet.Name);                           
                        }
                    });
                }  
            });

            if (spfDisabledDnsRecords.length) {
                helpers.addResult(results, 2,
                    `Hosted Zone has these SPF disabled DNS records: ${spfDisabledDnsRecords.join(', ')}`,
                    region, resource);
                
            } else {
                helpers.addResult(results, 0,
                    'Hosted Zone has SPF enabled for all DNS records',
                    region, resource);
            }

            cb();
        }, function(){
            callback(null, results, source);
        });
    }
};
