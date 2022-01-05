var async = require('async');
var helpers = require('../../../helpers/aws');
module.exports = {
    title: 'KMS Grant Least Privilege',
    category: 'KMS',
    domain: 'Application Integration',
    description: 'Ensure that AWS KMS key grants use the principle of least privileged access.',
    more_info: 'AWS KMS key grants should be created with minimum set of permissions required by grantee principal to adhere to AWS security best practices.',
    recommended_action: 'Create KMS grants with minimum permission required',
    link: 'https://docs.aws.amazon.com/kms/latest/developerguide/grants.html',
    apis: ['KMS:listKeys', 'KMS:listGrants', 'KMS:describeKey'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var symmetricOperations = [
            'Decrypt',
            'Encrypt',
            'GenerateDataKey',
            'GenerateDataKeyPair',
            'GenerateDataKeyPairWithoutPlaintext',
            'GenerateDataKeyWithoutPlaintext',
            'ReEncryptFrom',
            'ReEncryptTo',
            'CreateGrant',
            'DescribeKey',
            'RetireGrant',
        ];

        var asymmetricEDOperations = [
            'Decrypt',
            'Encrypt',
            'ReEncryptFrom',
            'ReEncryptTo',
            'CreateGrant',
            'DescribeKey',
            'GetPublicKey',
            'RetireGrant',
        ];

        var asymmetricSVOperations = [ // eslint-disable-line
            'ReEncryptFrom',
            'ReEncryptTo',
            'Sign',
            'Verify',
            'CreateGrant',
            'DescribeKey',
            'GetPublicKey',
            'RetireGrant',
        ];

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

                let keySpec = describeKey.data.KeyMetadata.KeySpec;
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

                let privilegedGrants = [];
                for (let grant of listGrants.data.Grants) {
                    if (keySpec && keySpec.startsWith('SYMMETRIC')) {
                        if (grant.Operations && grant.Operations.length &&
                            grant.Operations.length >= symmetricOperations.length) privilegedGrants.push(grant.GrantId);
                    } else {
                        if (grant.Operations && grant.Operations.length &&
                            grant.Operations.length >= asymmetricEDOperations.length) privilegedGrants.push(grant.GrantId);
                    }
                }

                if (privilegedGrants.length) {
                    helpers.addResult(results, 2,
                        `KMS key provides * permission for these grants: ${privilegedGrants.join(', ')}`, region, resource);
                } else {
                    helpers.addResult(results, 0,
                        'KMS key does not provide * permission for any grants', region, resource);
                }
            });

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};