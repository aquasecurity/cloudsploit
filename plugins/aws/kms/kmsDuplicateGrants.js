var async = require('async');
var helpers = require('../../../helpers/aws');
module.exports = {
    title: 'KMS Duplicate Grants',
    category: 'KMS',
    domain: 'Application Integration',
    description: 'Ensure that AWS KMS keys does not have duplicate grants to adhere to AWS security best practices.',
    more_info: 'Duplicate grants have the same key ARN, API actions, grantee principal, encryption context, and name. ' +
        'If you retire or revoke the original grant but leave the duplicates, the leftover duplicate grants constitute unintended escalations of privilege.',
    recommended_action: 'Delete duplicate grants for AWS KMS keys',
    link: 'https://docs.aws.amazon.com/kms/latest/developerguide/grants.html',
    apis: ['KMS:listKeys', 'KMS:listGrants', 'KMS:describeKey'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.kms, function(region, rcb){
            var listKeys = helpers.addSource(cache, source,
                ['kms', 'listKeys', region]);

            if (!listKeys) return rcb();

            if (listKeys.err || !listKeys.data){
                helpers.addResult(results, 3,
                    'Unable to list KMS keys: ' + helpers.addError(listKeys), region);
                return rcb();
            }

            if (!listKeys.data.length){
                helpers.addResult(results, 0, 'No KMS keys found', region);
                return rcb();
            }

            listKeys.data.forEach(kmsKey => {
                let resource = kmsKey.KeyArn;
                let describeKey = helpers.addSource(cache, source,
                    ['kms', 'describeKey', region, kmsKey.KeyId]);

                if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
                    helpers.addResult(results, 3,
                        `Unable to query for KMS Key: ${helpers.addError(describeKey)}`,
                        region, resource);
                    return;
                }

                let keyLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);

                if (keyLevel == 2) {
                    helpers.addResult(results, 0,
                        'KMS key is AWS-managed', region, resource);
                    return;
                }

                let listGrants = helpers.addSource(cache, source,
                    ['kms', 'listGrants', region, kmsKey.KeyId]);

                if (!listGrants || listGrants.err || !listGrants.data || !listGrants.data.Grants) {
                    helpers.addResult(results, 3,
                        `Unable to query for KMS Key grants: ${helpers.addError(describeKey)}`,
                        region, resource);
                    return;
                }

                if (!listGrants.data.Grants.length) {
                    helpers.addResult(results, 0,
                        'No grants exist for the KMS key',
                        region, resource);
                    return;
                }

                let found = false;
                for (let entry of listGrants.data.Grants) {
                    let dupGrant = listGrants.data.Grants.filter(grant => grant.KeyId === entry.KeyId &&
                        grant.Name === entry.Name &&
                        grant.GranteePrincipal == entry.GranteePrincipal &&
                        (grant.Operations && entry.Operations) ? JSON.stringify(grant.Operations) == JSON.stringify(entry.Operations) : true &&
                        (grant.Constraints && entry.Constraints) ? JSON.stringify(grant.Constraints) == JSON.stringify(entry.Constraints) : true);
                    if (dupGrant && dupGrant.length > 1) found = true;
                }
                
                
                if (found) {
                    helpers.addResult(results, 2,
                        'KMS key has duplicate grants', region, resource);
                } else {
                    helpers.addResult(results, 0,
                        'KMS key does not have duplicate grants', region, resource);
                }
            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
}; 