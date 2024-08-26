var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Ledger Deletion Protection',
    category: 'QLDB',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensures that AWS QLDB ledger has deletion protection feature enabled.',
    more_info: 'Enabling deletion protection feature for Amazon QLDB ledger acts as a safety net, preventing accidental database deletions or deletion by an unauthorized user. It ensures that the data stays secure and accessible at all times.',
    recommended_action: 'Modify QLDB ledger and enable deletion protection.',
    link: 'https://docs.aws.amazon.com/qldb/latest/developerguide/ledger-management.basics.html',
    apis: ['QLDB:listLedgers','QLDB:describeLedger','STS:getCallerIdentity'],
    realtime_triggers: ['qldb:CreateLedger', 'qldb:UpdateLedger', 'qldb:DeleteLedger'], 

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

            for (let ledger of listLedgers.data) {
                if (!ledger.Name) continue;

                let resource = `arn:${awsOrGov}:qldb:${region}:${accountId}:ledger/${ledger.Name}`;

                var describeLedger = helpers.addSource(cache, source,
                    ['qldb', 'describeLedger', region, ledger.Name]);

                if (!describeLedger || describeLedger.err || !describeLedger.data ) {
                    helpers.addResult(results, 3,
                        `Unable to get QLDB ledgers description: ${helpers.addError(describeLedger)}`,
                        region, resource);
                    continue;
                } 

                if (describeLedger.data.DeletionProtection) {
                    helpers.addResult(results, 0,
                        'QLDB ledger has deletion protection enabled',
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        'QLDB ledger does not have deletion protection enabled',
                        region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};