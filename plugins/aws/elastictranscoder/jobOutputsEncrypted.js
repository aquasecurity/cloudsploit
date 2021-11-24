var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Elastic Transcoder Job Outputs Encrypted',
    category: 'Elastic Transcoder',
    domain: 'Application Integration',
    description: 'Ensure that Elastic Transcoder jobs have encryption enabled to encrypt your data before saving on S3.',
    more_info: 'Amazon Elastic Transcoder jobs saves th result output on S3. If you don\'t configure encryption parameters, these job will save the file unencrypted. ' +
        'You should enabled encryption for output files and use customer-managed keys for encryption in order to gain more granular control over encryption/decryption process',
    recommended_action: 'Enable encryption for Elastic Transcoder job outputs',
    link: 'https://docs.aws.amazon.com/elastictranscoder/latest/developerguide/encryption.html',
    apis: ['ElasticTranscoder:listPipelines', 'ElasticTranscoder:listJobsByPipeline'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.elastictranscoder, function(region, rcb){
            var listPipelines = helpers.addSource(cache, source,
                ['elastictranscoder', 'listPipelines', region]);

            if (!listPipelines) return rcb();

            if (listPipelines.err || !listPipelines.data) {
                helpers.addResult(results, 3,
                    `Unable to list Elastic Transcoder pipelines: ${helpers.addError(listPipelines)}`, region);
                return rcb();
            }

            if (!listPipelines.data.length) {
                helpers.addResult(results, 0,
                    'No Elastic Transcoder pipelines found', region);
                return rcb();
            }

            for (let pipeline of listPipelines.data) {
                if (!pipeline.Id) continue;

                let pipelineJobs = helpers.addSource(cache, source,
                    ['elastictranscoder', 'listJobsByPipeline', region, pipeline.Id]);

                if (!pipelineJobs || pipelineJobs.err || !pipelineJobs.data || !pipelineJobs.data.Jobs) {
                    helpers.addResult(results, 3,
                        `Unable to list Elastic Transcoder jobs for pipeline: ${helpers.addError(pipelineJobs)}`, region, pipeline.Arn);
                    continue;
                }
    
                if (!pipelineJobs.data.Jobs.length) {
                    helpers.addResult(results, 0,
                        'No Elastic Transcoder jobs found for pipeline', region, pipeline.Arn);
                    continue;
                }

                for (let job of pipelineJobs.data.Jobs) {
                    if (job.Status && job.Status.toUpperCase() == 'ERROR') {
                        helpers.addResult(results, 0,
                            'Job status is "Error"', region, job.Arn);
                    } else {
                        if (job.Outputs && job.Outputs.length) var unencryptedOutputs = job.Outputs.find(output => !output.Encryption);
                        else helpers.addResult(results, 0, 'Job does not have any outputs', region, job.Arn);

                        if (unencryptedOutputs) {
                            helpers.addResult(results, 2,
                                'Job does not encryption enabled for one or more outputs', region, job.Arn);
                        } else {
                            helpers.addResult(results, 0,
                                'Job has encryption enabled for outputs', region, job.Arn);
                        }
                    }
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};