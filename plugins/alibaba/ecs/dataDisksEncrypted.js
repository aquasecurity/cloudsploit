var async = require('async');
var helpers = require('../../../helpers/alibaba');

var encryptionLevels = ['none', 'sse', 'cloudkms', 'alibabacmk', 'externalcmk', 'cloudhsm'];

function getEncryptionLevel(kmsKey) {
    if (kmsKey.Origin) {
        if (kmsKey.Origin === 'Aliyun_KMS') {
            if (kmsKey.ProtectionLevel) {
                if (kmsKey.ProtectionLevel.toUpperCase() == 'SOFTWARE') return 3;
                if (kmsKey.ProtectionLevel.toUpperCase() == 'HSM') return 5;
            }
        }
        if (kmsKey.Origin === 'EXTERNAL') return 4;
    }

    return 0;
}

module.exports = {
    title: 'Data Disks Encrypted',
    category: 'ECS',
    description: 'Ensure that encryption is enabled for ECS data disk volumes.',
    more_info: 'Encryption can help you secure your data stored in Alibaba Cloud ECS and comply with security standards.',
    link: 'https://www.alibabacloud.com/help/doc-detail/59643.htm',
    recommended_action: 'Enable encryption for ECS data disk volumes.',
    apis: ['ECS:DescribeDisks', 'KMS:ListKeys', 'KMS:DescribeKey', 'STS:GetCallerIdentity'],
    compliance: {
        hipaa: 'HIPAA requires that all data is encrypted, including data at rest. ' +
                'ECS disk is a HIPAA-compliant solution that provides automated encryption ' +
                'of ECS instance data at rest.',
        pci: 'PCI requires proper encryption of cardholder data at rest. Encryption ' +
             'should be enabled for all disk volumes storing this type of data.'
    },
    settings: {
        data_disks_encryption_level: {
            name: 'ECS Data Disks Encryption Level',
            description: 'In order (lowest to highest) cloudkms=Alibaba managed default service KMS; alibabacmk=Customer managed KMS; externalcmk=Customer imported key; cloudhsm=Customer managed CloudHSM sourced Key',
            regex: '^(cloudkms|alibabacmk|externalcmk|cloudhsm)$',
            default: 'cloudkms',
        },
        data_disks_result_limit: {
            name: 'Data Disks Result Limit',
            description: 'If the number of results is greater than this value, combine them into one result',
            regex: '^[0-9]*$',
            default: '20',
        },
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
        var defaultRegion = helpers.defaultRegion(settings);

        var accountId = helpers.addSource(cache, source, ['sts', 'GetCallerIdentity', defaultRegion, 'data']);

        var targetEncryptionLevel = encryptionLevels.indexOf(settings.data_disks_encryption_level || this.settings.data_disks_encryption_level.default);
        var disksResultLimit = parseInt(settings.data_disks_result_limit || this.settings.data_disks_result_limit.default);

        async.each(regions.ecs, function(region, rcb) {
            var describeDisks = helpers.addSource(cache, source, ['ecs', 'DescribeDisks', region]);
            if (!describeDisks) return rcb();

            if (describeDisks.err || !describeDisks.data) {
                helpers.addResult(results, 3, 'Unable to query ECS disks: ' + helpers.addError(describeDisks), region);
                return rcb();
            }

            if (!describeDisks.data.length) {
                helpers.addResult(results, 0, 'No ECS disks found', region);
                return rcb();
            }

            var listKeys = helpers.addSource(cache, source, ['kms', 'ListKeys', region]);

            if (!listKeys || listKeys.err || !listKeys.data) {
                helpers.addResult(results, 3, 'Unable to query KMS keys: ' + helpers.addError(listKeys), region);
                return rcb();
            }

            var encryptionFailing = [];
            var encryptionPassing = [];
            var keyErrors = [];
            var found = false;
          
            async.each(describeDisks.data, (disk, dcb) => {
                if (!disk.DiskId || disk.Type.toLowerCase() !== 'data') return dcb();

                found = true;
                if (!disk.Encrypted) {
                    encryptionFailing.push(disk.DiskId);
                    return dcb();
                }

                if (!disk.KMSKeyId || !disk.KMSKeyId.length) {
                    if (targetEncryptionLevel > 2) {
                        encryptionFailing.push(disk.DiskId);
                    } else encryptionPassing.push(disk.DiskId);
                    return dcb();
                }

                var describeKey = helpers.addSource(cache, source, ['kms', 'DescribeKey', region, disk.KMSKeyId]);

                if (!describeKey || describeKey.err || !describeKey.data) {
                    keyErrors.push({ kmsKeyId: disk.KMSKeyId, err: helpers.addError(describeKey) });
                    return dcb();
                }

                var currentEncryptionLevel = getEncryptionLevel(describeKey.data);

                if (currentEncryptionLevel < targetEncryptionLevel) {
                    encryptionFailing.push(disk.DiskId);
                } else encryptionPassing.push(disk.DiskId);
                
                dcb();
            }, function() {
                if (encryptionFailing.length) {
                    if (encryptionFailing.length > disksResultLimit) {
                        helpers.addResult(results, 2, `More than ${disksResultLimit} data disks are not encrypted to ${encryptionLevels[targetEncryptionLevel]}`, region);
                    } else {
                        encryptionFailing.forEach(diskId => {
                            let resource = helpers.createArn('ecs', accountId, 'disk', diskId, region);
                            helpers.addResult(results, 2, `Data disk is not encrypted to ${encryptionLevels[targetEncryptionLevel]}`, region, resource);
                        });
                    }
                }

                if (keyErrors.length) {
                    if (keyErrors.length > disksResultLimit) {
                        helpers.addResult(results, 3, `More than ${disksResultLimit} errors describing kms keys happened`, region);
                    } else {
                        keyErrors.forEach(({err, kmsKeyId}) => {
                            let resource = helpers.createArn('kms', accountId, 'key', kmsKeyId, region);
                            helpers.addResult(results, 3, `Unable to describe KMS key: ${err}`, region, resource);
                        });
                    }
                }

                if (encryptionPassing.length) {
                    if (encryptionPassing.length > disksResultLimit) {
                        helpers.addResult(results, 0, `More than ${disksResultLimit} data disks are encrypted to at least ${encryptionLevels[targetEncryptionLevel]}`,
                            region);
                    } else {
                        encryptionPassing.forEach(diskId => {
                            let resource = helpers.createArn('ecs', accountId, 'disk', diskId, region);
                            helpers.addResult(results, 0, `Data disk is encrypted to at least ${encryptionLevels[targetEncryptionLevel]}`,
                                region, resource);
                        });
                    }
                }

                if (!found) {
                    helpers.addResult(results, 0, 'No ECS data disks found', region);
                }
                
                rcb();
            });
        }, function(){
            callback(null, results, source);
        });
    }
};
