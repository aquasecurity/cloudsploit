var async = require('async');
var helpers = require('../../../helpers/aws');

const encryptionLevelMap = {
    none: 0,
    sse: 1,
    awskms: 2,
    awscmk: 3,
    externalcmk: 4,
    cloudhsm: 5,
    0: 'none',
    1: 'sse',
    2: 'awskms',
    3: 'awscmk',
    4: 'externalcmk',
    5: 'cloudhsm',
};

function getEncryptionLevel(kmsKey) {
    if (kmsKey.Origin === 'AWS_KMS') {
        if (kmsKey.KeyManager === 'AWS') {
            return 2;
        } else if (kmsKey.KeyManager === 'CUSTOMER') {
            return 3;
        }
    }
    if (kmsKey.Origin === 'EXTERNAL') {
        return 4;
    }
    if (kmsKey.Origin === 'AWS_CLOUDHSM') {
        return 5;
    }
}

module.exports = {
    title: 'EBS Encryption Enabled',
    category: 'EC2',
    domain: 'Compute',
    description: 'Ensures EBS volumes are encrypted at rest',
    more_info: 'EBS volumes should have at-rest encryption enabled through AWS using KMS. If the volume is used for a root volume, the instance must be launched from an AMI that has been encrypted as well.',
    link: 'http://docs.aws.amazon.com/AWSEC2/latest/UserGuide/EBSEncryption.html',
    recommended_action: 'Enable encryption for EBS volumes.',
    apis: ['EC2:describeVolumes', 'KMS:describeKey', 'KMS:listKeys',  'STS:getCallerIdentity'],
    compliance: {
        hipaa: 'HIPAA requires that all data is encrypted, including data at rest. ' +
                'EBS is a HIPAA-compliant solution that provides automated encryption ' +
                'of EC2 instance data at rest.',
        pci: 'PCI requires proper encryption of cardholder data at rest. EBS ' +
             'encryption should be enabled for all volumes storing this type ' +
             'of data.'
    },
    settings: {
        ebs_encryption_level: {
            name: 'EBS Minimum Encryption Level at rest',
            description: 'In order (lowest to highest) awskms=AWS-managed KMS; awscmk=Customer managed KMS; externalcmk=Customer managed externally sourced KMS; cloudhsm=Customer managed CloudHSM sourced KMS',
            regex: '^(awskms|awscmk|externalcmk|cloudhsm)$',
            default: 'awscmk',
        },
       
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);
        var targetEncryptionLevel = encryptionLevelMap[settings.ebs_encryption_level || this.settings.ebs_encryption_level.default];

        async.each(regions.ec2, function(region, rcb) {
            var describeVolumes = helpers.addSource(cache, source, ['ec2', 'describeVolumes', region]);

            if (!describeVolumes) return rcb();
            if (describeVolumes.err || !describeVolumes.data) {
                helpers.addResult(results, 3, 'Unable to query for EBS volumes: ' + helpers.addError(describeVolumes), region);
                return rcb();
            }
            if (!describeVolumes.data.length) {
                helpers.addResult(results, 0, 'No EBS volumes present', region);
                return rcb();
            }

            for (let volume of describeVolumes.data) {
                var resource = 'arn:' + awsOrGov + ':ec2:' + region + ':' + accountId + ':volume/' + volume.VolumeId;
                if (!volume.Encrypted || !volume.KmsKeyId){
                    helpers.addResult(results, 2, 'EBS volume is unencrypted', region, resource);
                    continue;
                }

                var kmsKeyId = volume.KmsKeyId.split('/')[1];
                var describeKey = helpers.addSource(cache, source, ['kms', 'describeKey', region, kmsKeyId]);
                if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
                    helpers.addResult(results, 3, 'Could not describe KMS key', region, volume.KmsKeyId);
                    continue;
                }

                var encryptionLevel = getEncryptionLevel(describeKey.data.KeyMetadata);

                if (encryptionLevel < targetEncryptionLevel) {
                    helpers.addResult(results, 1,
                        `EBS volume is not encrypted to ${encryptionLevelMap[targetEncryptionLevel]}`,
                        region, resource);
                } else {
                    helpers.addResult(results, 0,
                        `EBS volume is encrypted to ${encryptionLevelMap[targetEncryptionLevel]}`,
                        region, resource);
                }
            }

          
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
