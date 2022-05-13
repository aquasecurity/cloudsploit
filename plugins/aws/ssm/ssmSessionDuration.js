var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'SSM Session Duration',
    category: 'SSM',
    domain: 'Identity Access and Management',
    severity: 'LOW',
    description: 'Ensure that all active sessions in the AWS Session Manager do not exceed the duration set in the settings.',
    more_info: 'The session manager gives users the ability to either open a shell in a EC2 instance or execute commands in a ECS task. This can be useful for when debugging issues in a container or instance.',
    recommended_action: 'Terminate all the sessions which exceed the specified duration mentioned in settings.',
    link: 'https://docs.aws.amazon.com/systems-manager/latest/userguide/session-preferences-max-timeout.html',
    apis: ['SSM:describeSessions'],
    settings: {
        ssm_session_max_duration: {
            name: 'Max Duration for SSM Session',
            description: 'Maximum duration in minutes for SSM session.',
            regex: '^((1440)|(14[0-3][0-9]{1})|(1[0-3][0-9]{2})|([1-9][0-9]{2})|([1-9][0-9]{1})|([1-9]))$',
            default: '5'
        }
    },

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var awsOrGov = helpers.defaultPartition(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        var sessionMaxDuration = settings.ssm_session_max_duration || this.settings.ssm_session_max_duration.default;

        if (!sessionMaxDuration || !sessionMaxDuration.trim().length) return callback(null, results, source);

        async.each(regions.ssm, function(region, rcb){
            var describeSessions = helpers.addSource(cache, source,
                ['ssm', 'describeSessions', region]);

            if (!describeSessions) return rcb();

            if (describeSessions.err || !describeSessions.data) {
                helpers.addResult(results, 3,
                    'Unable to query for active SSM sessions: ' + helpers.addError(describeSessions), region);
                return rcb();
            }

            if (!describeSessions.data.length) {
                helpers.addResult(results, 0,
                    'No Active SSM sessions found: ' + helpers.addError(describeSessions), region);
                return rcb();
            }

            const uniqInstances = describeSessions.data.filter((value, index, self) =>
                index === self.findIndex((t) => (t.Target && value.Target && t.Target === value.Target))
            );

            const sessionsByInstances = uniqInstances.map((instance) => {
                return { instanceId: instance.Target, sessions: describeSessions.data.filter(session => session.Target === instance.Target) };
            });

            for (let instance of sessionsByInstances) {
                var resource = `arn:${awsOrGov}:ec2:${region}:${accountId}:/instance/${instance.instanceId}`;

                let failingSessions = '';
                for (let session of instance.sessions) {
                    let activeSessionTimeInMins = helpers.minutesBetween(new Date(), session.StartDate);
                    
                    if (sessionMaxDuration && sessionMaxDuration < activeSessionTimeInMins) {
                        failingSessions += `${session.SessionId} - ${activeSessionTimeInMins} mins\n`;
                    }
                }

                if (failingSessions.length) {
                    helpers.addResult(results, 2,
                        `Following SSM Sessions duration length is greater than \
                        the max time threshold: ${failingSessions}`,
                        region, resource);
                } else {
                    helpers.addResult(results, 0,
                        'All SSM Sessions duration length is less than the max time threshold', region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
