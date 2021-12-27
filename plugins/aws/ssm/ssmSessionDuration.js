var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'SSM Session Duration',
    category: 'SSM',
    domain: 'Identity Access and Management',
    description: 'Ensure that all active sessions in the AWS Session Manager do not exceed the duration set in the settings.',
    more_info: 'The session manager gives users the ability to either open a shell in a EC2 instance or execute commands in a ECS task. This can be useful for when debugging issues in a container or instance.',
    recommended_action: 'Terminate all the sessions which exceed the specified duration mentioned in settings.',
    link: 'https://docs.aws.amazon.com/systems-manager/latest/userguide/session-preferences-max-timeout.html',
    apis: ['SSM:describeSessions'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        async.each(regions.ssm, function(region, rcb){
            var describeSessions = helpers.addSource(cache, source,
                ['ssm', 'describeSessions', region]);

            if (!describeSessions) return rcb();

            if (describeSessions.err || !describeSessions.data) {
                helpers.addResult(results, 3,
                    'Unable to query for active ssm sessions: ' + helpers.addError(describeSessions), region);
                return rcb();
            }

            if (!describeSessions.data.length) {
                helpers.addResult(results, 0,
                    'No Active SSM sessions found: ' + helpers.addError(describeSessions), region);
                return rcb();
            }

            for (let session of describeSessions.data) {
                let resource = session.SessionId;
                let activeSessionTimeInMins = Math.floor((Math.abs(new Date() - new Date(session.StartDate)))/1000/60);

                if (session.MaxSessionDuration) {
                    if (session.MaxSessionDuration > activeSessionTimeInMins) {
                        helpers.addResult(results, 0,
                            `SSM Session duration length is ${activeSessionTimeInMins} minutes which is less than the \
                            max time set in SSM Session Manager ${session.MaxSessionDuration} minutes`,
                            region, resource);
                    } else {
                        helpers.addResult(results, 2,
                            `SSM Session duration length is ${activeSessionTimeInMins} minutes which is greater than \
                            the max time set in SSM Session Manager ${session.MaxSessionDuration} minutes`, region, resource);
                    }
                } else {
                    helpers.addResult(results, 1,
                        'SSM Session max duration length is not set. Please set the maximum session duration \
                        length in SSM Session Manager', region, resource);
                }
            }

            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
