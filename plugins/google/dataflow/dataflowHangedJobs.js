var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Dataflow Hanged Jobs',
    category: 'Dataflow',
    description: 'Ensure that Cloud Dataflow jobs are not in same state for more than defined amount of time.',
    more_info: 'Cloud Dataflow jobs transit between different states and normally reach terminal state. If they stay in same state ' +
        'for abnormal amount of time, job administrator should stop such jobs to save unnecessary cost.',
    link: 'https://cloud.google.com/sdk/gcloud/reference/dataflow/jobs/cancel',
    recommended_action: 'Cancel/stop Dataflow jobs which are in same state for more than set amount of time',
    apis: ['jobs:list'],
    settings: {
        dataflow_job_state_time: {
            name: 'Dataflow Job Maximum State Time',
            description: 'Maximum allowed amount of time in hours for a Dataflow job state',
            regex: '^(0?[1-9]|[1-9][0-9])$',
            default: '6'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        var config = {
            dataflow_job_state_time: parseInt(settings.dataflow_job_state_time || this.settings.dataflow_job_state_time.default)
        };

        async.each(regions.jobs, function(region, rcb){
            let jobs = helpers.addSource(cache, source,
                ['jobs', 'list', region]);

            if (!jobs) return rcb();

            if (jobs.err || !jobs.data) {
                helpers.addResult(results, 3, 'Unable to query Dataflow jobs: ' + helpers.addError(jobs), region);
                return rcb();
            }

            if (!jobs.data.length) {
                helpers.addResult(results, 0, 'No Dataflow jobs found', region);
                return rcb();
            }

            async.each(jobs.data, (job, cb) => {
                if (!job.id) return cb();

                let resource = `projects/${job.projectId}/jobs/${job.id}`;

                if (job.currentState && !['JOB_STATE_RUNNING', 'JOB_STATE_DRAINING', 'JOB_STATE_CANCELLING'].includes(job.currentState.toUpperCase())) {
                    helpers.addResult(results, 0,
                        'Dataflow job has completed', region, resource);
                    return cb();
                }

                let stateTime = job.currentStateTime || new Date();
                let now = new Date();

                let difference = helpers.hoursBetween(now, stateTime);
                let status = (difference > config.dataflow_job_state_time) ? 2 : 0;
                
                helpers.addResult(results, status,
                    `Dataflow job is in ${job.currentState} for ${difference} hours`,
                    region, resource);

                cb();
            }, function(){
                rcb();
            });
        }, function(){
            callback(null, results, source);
        });
    }
};
