var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Managed Blockchain Network Member Data Encrypted',
    category: 'Managed Blockchain',
    domain: 'Content Delivery',
    description: 'Ensure that members created in Amazon Managed Blockchain are encrtypted using desired encryption level.',
    more_info: 'Amazon Managed Blockchain encrypts the network member data at-rest by default with AWS-managed keys. ' +
        'Use your own key (CMK) to encrypt this data to meet regulatory compliance requirements within your organization',
    link: 'https://docs.aws.amazon.com/managed-blockchain/latest/hyperledger-fabric-dev/managed-blockchain-encryption-at-rest.html',
    recommended_action: 'Ensure members in Managed Blockchain are using desired encryption level for encryption',
    apis: ['ManagedBlockchain:listMembers', 'ManagedBlockchain:listNetworks', 'ManagedBlockchain:getMember', 'KMS:listKeys', 'KMS:describeKey'],
    settings: {
        blockchain_member_encryption_level: {
            name: 'Managed Blockchain Member Target Encryption Level',
            description: 'In order (lowest to highest) sse=S3-SSE; awscmk=Customer managed KMS; externalcmk=Customer managed externally sourced KMS; cloudhsm=Customer managed CloudHSM sourced KMS',
            regex: '^(awskms|awscmk|externalcmk|cloudhsm)$',
            default: 'awscmk',
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var config = {
            desiredEncryptionLevelString: settings.blockchain_member_encryption_level || this.settings.blockchain_member_encryption_level.default
        };

        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
        var currentEncryptionLevel;

        async.each(regions.managedblockchain, function(region, rcb){
            var listNetworks = helpers.addSource(cache, source,
                ['managedblockchain', 'listNetworks', region]);

            if (!listNetworks) return rcb();

            if (listNetworks.err || !listNetworks.data) {
                helpers.addResult(results, 3,
                    `Unable to query for Managed Blockchain networks: ${helpers.addError(listNetworks)}`, region);
                return rcb();
            }

            if (!listNetworks.data.length) {
                helpers.addResult(results, 0, 'No Managed Blockchain networks found', region);
                return rcb();
            }

            for (let network of listNetworks.data) {
                if (!network.Id || !network.Arn) continue;
                
                let listMembers = helpers.addSource(cache, source,
                    ['managedblockchain', 'listMembers', region, network.Id]);

                if (!listMembers || listMembers.err || !listMembers.data || !listMembers.data.Members) {
                    helpers.addResult(results, 3,
                        `Unable to query network members: ${helpers.addError(listMembers)}`,
                        region, network.Arn);
                    continue;
                }

                if (!listMembers.data.Members.length) {
                    helpers.addResult(results, 0, 'No network members found', region, network.Arn);
                    continue;
                }

                var listKeys = helpers.addSource(cache, source,
                    ['kms', 'listKeys', region]);
    
                if (!listKeys || listKeys.err || !listKeys.data) {
                    helpers.addResult(results, 3,
                        `Unable to list KMS keys: ${helpers.addError(listKeys)}`, region);
                    return rcb();
                }

                for (let member of listMembers.data.Members) {
                    if (!member.Id || !member.Arn) continue;

                    let resource = member.Arn;
                    let getMember = helpers.addSource(cache, source,
                        ['managedblockchain', 'getMember', region, member.Id]);
    
                    if (!getMember || getMember.err || !getMember.data || !getMember.data.Member) {
                        helpers.addResult(results, 3,
                            `Unable to query network member: ${helpers.addError(getMember)}`,
                            region, member.Arn);
                        continue;
                    }

                    if (getMember.data.Member.KmsKeyArn) {
                        if (getMember.data.Member.KmsKeyArn === 'AWS_OWNED_KMS_KEY') {
                            currentEncryptionLevel = 2;
                        } else {
                            var kmsKeyId = getMember.data.Member.KmsKeyArn.split('/')[1] ? getMember.data.Member.KmsKeyArn.split('/')[1] : getMember.data.Member.KmsKeyArn;
    
                            var describeKey = helpers.addSource(cache, source,
                                ['kms', 'describeKey', region, kmsKeyId]);
    
                            if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
                                helpers.addResult(results, 3,
                                    `Unable to query KMS key: ${helpers.addError(describeKey)}`,
                                    region, kmsKeyId);
                                continue;
                            }
    
                            currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
                        }
                    } else {
                        currentEncryptionLevel = 2; //awskms
                    }

                    var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];

                    if (currentEncryptionLevel >= desiredEncryptionLevel) {
                        helpers.addResult(results, 0,
                            `Network member is using ${currentEncryptionLevelString} for encryption \
                            which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
                            region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            `Network member is using ${currentEncryptionLevelString} for encryption \
                            which is less than the desired encryption level ${config.desiredEncryptionLevelString}`,
                            region, resource);
                    }
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
