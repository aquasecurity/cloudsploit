var async = require('async');
var helpers = require('../../../helpers/aws');

module.exports = {
    title: 'Workgroup Enforce Configuration',
    category: 'Athena',
    description: 'Ensures Athena workgroups do not allow clients to override configuration options.',
    more_info: 'Athena workgroups support the ability for clients to override configuration options, including encryption requirements. This setting should be disabled to enforce encryption mandates.',
    link: 'https://docs.aws.amazon.com/athena/latest/ug/workgroups-settings.html',
    recommended_action: 'Disable the ability for clients to override Athena workgroup configuration options.',
    apis: ['Athena:listWorkGroups', 'Athena:getWorkGroup', 'STS:getCallerIdentity'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions(settings);

        var acctRegion = helpers.defaultRegion(settings);
        var accountId = helpers.addSource(cache, source, ['sts', 'getCallerIdentity', acctRegion, 'data']);

        async.each(regions.athena, function(region, rcb){
            var listWorkGroups = helpers.addSource(cache, source,
                ['athena', 'listWorkGroups', region]);

            if (!listWorkGroups) return rcb();

            if (listWorkGroups.err || !listWorkGroups.data) {
                helpers.addResult(results, 3,
                    'Unable to list Athena workgroups: ' + helpers.addError(listWorkGroups), region);
                return rcb();
            }

            if (!listWorkGroups.data.length) {
                helpers.addResult(results, 0, 'No Athena workgroups found', region);
                return rcb();
            }

            // Loop through certificates
            listWorkGroups.data.forEach(function(wg){
                var getWorkGroup = helpers.addSource(cache, source,
                    ['athena', 'getWorkGroup', region, wg.Name]);

                // arn:aws:athena:region:account-id:workgroup/workgroup-name
                var arn = 'arn:aws:athena:' + region + ':' + accountId + ':workgroup/' + wg.Name;

                if (!getWorkGroup || getWorkGroup.err || !getWorkGroup.data) {
                    helpers.addResult(results, 3,
                        'Unable to describe Athena workgroup: ' + helpers.addError(getWorkGroup), region, arn);
                } else if (getWorkGroup.data.WorkGroup &&
                           getWorkGroup.data.WorkGroup.Configuration &&
                           getWorkGroup.data.WorkGroup.Configuration.EnforceWorkGroupConfiguration) {
                    helpers.addResult(results, 0,
                        'Athena workgroup is enforcing configuration options', region, arn);
                } else {
                    // Check for empty primary workgroups
                    if (wg.Name == 'primary' &&
                        (!getWorkGroup.data.WorkGroup ||
                         !getWorkGroup.data.WorkGroup.Configuration ||
                         !getWorkGroup.data.WorkGroup.Configuration.ResultConfiguration ||
                         !getWorkGroup.data.WorkGroup.Configuration.ResultConfiguration.OutputLocation)) {
                        helpers.addResult(results, 0, 'Athena primary workgroup is not enforcing configuration options but is not in use', region, arn);
                    } else {
                        helpers.addResult(results, 2, 'Athena workgroup is not enforcing configuration options', region, arn);
                    }
                }
            });
            rcb();
        }, function(){
            callback(null, results, source);
        });
    }
};
