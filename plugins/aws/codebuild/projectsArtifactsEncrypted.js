var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Projects Artifact Encrypted',
    category: 'CodeBuild',
    domain: 'Application Integration',
    description: 'Ensure that your Amazon Projects Artifact are encrypted with desired encryption level.',
    more_info: 'Build artifacts'+
    'such as a cache, logs, exported raw test report data files, and build results'+
    'are encrypted by default using AWS managed keys.',
    recommended_action: 'Encrypt them using customer-managed keys to gain more control over data encryption and decryption process.',
    link: 'https://docs.aws.amazon.com/codebuild/latest/userguide/security-encryption.html',
    apis: ['CodeBuild:listProjects', 'CodeBuild:batchGetProjects', 'KMS:listKeys', 'KMS:describeKey'],
    settings: {
        projects_artifact_desired_encryption_level: {
            name: 'projects artifact target Encryption Level',
            description: 'In order (lowest to highest) awskms=AWS-managed KMS; awscmk=Customer managed KMS; externalcmk=Customer managed externally sourced KMS; cloudhsm=Customer managed CloudHSM sourced KMS',
            regex: '^(awskms|awscmk|externalcmk|cloudhsm)$',
            default: 'awscmk',
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);
       

        var config = {
            desiredEncryptionLevelString: settings.projects_artifact_desired_encryption_level || this.settings.projects_artifact_desired_encryption_level.default
        };

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source,
            ['sts', 'getCallerIdentity', acctRegion, 'data']);

        
        var desiredEncryptionLevel = helpers.ENCRYPTION_LEVELS.indexOf(config.desiredEncryptionLevelString);
        var currentEncryptionLevel;
   
        async.each(regions.codebuild, function(region, rcb){
            var listProjects = helpers.addSource(cache, source,
                ['codebuild', 'listProjects', region]);
            
            if (!listProjects) return rcb();

            if (listProjects.err || !listProjects.data) {
                helpers.addResult(results, 3,
                    `Unable to list projects: ${helpers.addError(listProjects)}`, region);
                return rcb();
            }

            if (!listProjects.data.length) {
                helpers.addResult(results, 0,
                    'No CodeBuild list projects found', region);
                return rcb();
            }

            var listKeys = helpers.addSource(cache, source,
                ['kms', 'listKeys', region]);

            if (!listKeys || listKeys.err || !listKeys.data) {
                helpers.addResult(results, 3,
                    `Unable to list KMS keys: ${helpers.addError(listKeys)}`, region);
                return rcb();
            }

            for (let project of listProjects.data) {
                var resource = `arn:${awsOrGov}:codebuild:${region}:${accountId}:project/${project}`;

                let batchGetProjects = helpers.addSource(cache, source,
                    ['codebuild', 'batchGetProjects', region, project]);

                if (!batchGetProjects || batchGetProjects.err || !batchGetProjects.data ||
                    !batchGetProjects.data.projects || !batchGetProjects.data.projects.length) {
                    helpers.addResult(results, 3,
                        `Unable to get batch projects: ${helpers.addError(batchGetProjects)}`, region, resource);
                    continue;
                }
                
                if (batchGetProjects.data.projects[0].encryptionKey && batchGetProjects.data.projects[0].encryptionKey.includes('alias/aws/s3')) {
                    currentEncryptionLevel = 2; //awskms
                } else if (batchGetProjects.data.projects[0].encryptionKey) {
                    var kmsKeyId = batchGetProjects.data.projects[0].encryptionKey.split('/')[1] ? batchGetProjects.data.projects[0].encryptionKey.split('/')[1] : batchGetProjects.data.projects[0].encryptionKey;
                    var describeKey = helpers.addSource(cache, source,
                        ['kms', 'describeKey', region, kmsKeyId]);

                    if (!describeKey || describeKey.err || !describeKey.data || !describeKey.data.KeyMetadata) {
                        helpers.addResult(results, 3,
                            `Unable to query KMS key: ${helpers.addError(describeKey)}`,
                            region, kmsKeyId);
                        continue;
                    }

                    currentEncryptionLevel = helpers.getEncryptionLevel(describeKey.data.KeyMetadata, helpers.ENCRYPTION_LEVELS);
                } else {
                    currentEncryptionLevel = 2; //awskms
                }

                var currentEncryptionLevelString = helpers.ENCRYPTION_LEVELS[currentEncryptionLevel];

                if (currentEncryptionLevel >= desiredEncryptionLevel) {
                    helpers.addResult(results, 0,
                        `CodeBuild project artifact is encrypted with ${currentEncryptionLevelString} \
                        which is greater than or equal to the desired encryption level ${config.desiredEncryptionLevelString}`,
                        region, resource);
                } else {
                    helpers.addResult(results, 2,
                        `CodeBuild project Artifact is encrypted with ${currentEncryptionLevelString} \
                        which is less than the desired encryption level ${config.desiredEncryptionLevelString}`,
                        region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
}; 