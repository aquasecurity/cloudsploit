var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Sender Privacy Framework Record Present',
    category: 'Route53',
    description: 'Ensure that Route 53 hosted zones have a DNS record containing Sender Policy Framework (SPF) value set for each MX record available.',
    more_info: 'The SPF record enables Route 53 registered domains to publicly state the mail servers that are authorized to send emails on its behalf.',
    link: 'https://docs.aws.amazon.com/Route53/latest/DeveloperGuide/resource-record-sets-creating.html',
    recommended_action: 'Add SPF records to the DNS records.',
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

            var spfRecordExists = listResourceRecordSets.data.ResourceRecordSets.find(
                recordSet => recordSet.Type && recordSet.Type.toUpperCase() === 'SPF');
            const status = spfRecordExists ? 0 : 2;

            helpers.addResult(results, status,
                `Hosted Zone '${zone.Name}' ${spfRecordExists ? 'has' : 'does not have any'} SPF record.`,
                region, resource);

            cb();
        }, function(){
            callback(null, results, source);
        });
    }
};
