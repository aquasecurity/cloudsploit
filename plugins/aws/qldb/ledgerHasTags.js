var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Ledger Has Tags',
    category: 'QLDB',
    domain: 'Databases',
    severity: 'Low',
    description: 'Ensure that AWS QLDB ledger has tags associated.',
    more_info: 'Tags help you to group resources together that are related to or associated with each other. It is a best practice to tag cloud resources to better organize and gain visibility into their usage.',
    recommended_action: 'Modify QLDB ledger and add tags.',
    link: 'https://docs.aws.amazon.com/qldb/latest/developerguide/tagging.html',
    apis: ['QLDB:listLedgers','ResourceGroupsTaggingAPI:getResources','STS:getCallerIdentity'],
    realtime_triggers: ['qldb:CreateLedger', 'qldb:DeleteLedger', 'qldb:TagResource', 'qldb:UntagResource'], 

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var defaultRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', defaultRegion, 'data']);

        async.each(regions.qldb, function(region, rcb){        
            var listLedgers = helpers.addSource(cache, source,
                ['qldb', 'listLedgers', region]);

            if (!listLedgers) return rcb();

            if (listLedgers.err || !listLedgers.data) {
                helpers.addResult(results, 3,
                    'Unable to query QLDB ledgers: ' + helpers.addError(listLedgers), region);
                return rcb();
            }

            if (!listLedgers.data.length) {
                helpers.addResult(results, 0, 'No QLDB ledgers found', region);
                return rcb();
            }

            const arnList = [];

            for (let ledger of listLedgers.data) {
                if (!ledger.Name) continue;

                let resource = `arn:${awsOrGov}:qldb:${region}:${accountId}:ledger/${ledger.Name}`;
                arnList.push(resource);
            }
            
            helpers.checkTags(cache, 'QLDB ledger', arnList, region, results, settings);

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};