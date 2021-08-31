var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Dataflow Jobs Encryption',
    category: 'Dataflow',
    description: 'Ensure that Google Dataflow jobs are encrypted with desired encryption level.',
    more_info: 'Google encrypts all jobs in Dataflow by default. Protecting source and sinks data for Dataflow batch pipeline with CMEK gives user more granular access to encryption and decryption process.',
    link: 'https://cloud.google.com/dataflow/docs/guides/customer-managed-encryption-keys',
    recommended_action: 'Use desired encryption level to encrypt Dataflow jobs.',
    apis: ['jobs:list', 'jobs:get', 'keyRings:list','cryptoKeys:list'],
    compliance: {
        hipaa: 'HIPAA requires that all data is encrypted, including data at rest. ' +
            'Enabling encryption for Dataflow jobs/pipelines helps to protect this data.',
        pci: 'PCI requires proper encryption of cardholder data at rest. ' +
            'Encryption should be enabled for all jobs storing this ' +
            'type of data.'
    },
    settings: {
        dataflow_job_encryption_level: {
            name: 'Dataflow Job Encryption Protection Level',
            description: 'Desired protection level for Dataflow jobs. default: google-managed, cloudcmek: customer managed encryption keys, ' +
                'cloudhsm: customer managed HSM ecnryption key, external: imported or externally managed key',
            regex: '^(default|cloudcmek|cloudhsm|external)$',
            default: 'cloudcmek'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        var config = {
            desiredEncryptionLevelStr: settings.dataflow_job_encryption_level || this.settings.dataflow_job_encryption_level.default
        };

        var desiredEncryptionLevel = helpers.PROTECTION_LEVELS.indexOf(config.desiredEncryptionLevelStr);
        var keysObj = {};

        async.series([
            function(cb){
                async.each(regions.cryptoKeys, function(region, rcb){
                    let cryptoKeys = helpers.addSource(
                        cache, source, ['cryptoKeys', 'list', region]);

                    if (cryptoKeys && cryptoKeys.data && cryptoKeys.data.length) helpers.listToObj(keysObj, cryptoKeys.data, 'name');
                    rcb();
                }, function(){
                    cb();
                });
            },
            function(cb){
                async.each(regions.jobs, function(jregion, jrcb){
                    let jobs = helpers.addSource(cache, source,
                        ['jobs', 'get', jregion]);
        
                    if (!jobs) return jrcb();
        
                    if (jobs.err || !jobs.data) {
                        helpers.addResult(results, 3, 'Unable to query Dataflow jobs: ' + helpers.addError(jobs), jregion);
                        return jrcb();
                    }
        
                    if (!jobs.data.length) {
                        helpers.addResult(results, 0, 'No Dataflow jobs found', jregion);
                        return jrcb();
                    }
    
                    async.each(jobs.data, (job, jcb) => {
                        if (!job.id) return jcb();

                        let currentEncryptionLevel;
                        let resource = `projects/${job.projectId}/jobs/${job.id}`;

                        if (job.type && job.type.toUpperCase() != 'JOB_TYPE_BATCH') {
                            helpers.addResult(results, 0,
                                `CMEK is not supported for ${job.type}`, jregion, resource);
                            return jcb();
                        }

                        if (!job.environment || !job.environment.serviceKmsKeyName || !job.environment.serviceKmsKeyName.length) {
                            currentEncryptionLevel = 1;
                        } else {
                            let cryptoKey = keysObj[job.environment.serviceKmsKeyName];
                            currentEncryptionLevel = helpers.getProtectionLevel(cryptoKey, helpers.PROTECTION_LEVELS);
                        }
    
                        let currentEncryptionLevelStr = helpers.PROTECTION_LEVELS[currentEncryptionLevel];
                        if (currentEncryptionLevel >= desiredEncryptionLevel) {
                            helpers.addResult(results, 0,
                                `Dataflow job is encrypted with ${currentEncryptionLevelStr} which is greater than or equal to ${config.desiredEncryptionLevelStr}`,
                                jregion, resource);
                        } else {
                            helpers.addResult(results, 2,
                                `Dataflow job is encrypted with ${currentEncryptionLevelStr} which is less than ${config.desiredEncryptionLevelStr}`,
                                jregion, resource);
                        }
    
                        jcb();
                    }, function(){
                        jrcb();
                    });
                }, function(){
                    cb();
                });
            }
        ], function(){
            callback(null, results, source);
        });
    }
};
