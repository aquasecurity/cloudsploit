var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'Any Host Root Access',
    category: 'SQL',
    description: 'Ensures SQL instances root user cannot be accessed from any host',
    more_info: 'Root access for SQL instance should only be allowed from whitelisted IPs to ensure secure access only from trusted entities.',
    link: 'https://cloud.google.com/sql/docs/mysql/create-manage-users',
    recommended_action: 'Ensure that root access for SQL instances are not allowed from any host.',
    apis: ['instances:sql:list', 'users:list'],

    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();

        async.each(regions.users, function(region, rcb){

            let users = helpers.addSource(cache, source,
                ['users', 'list', region]);

            if (!users) return rcb();

            if (users.err || !users.data) {
                helpers.addResult(results, 3, 'Unable to query SQL users: ' + helpers.addError(users), region);
                return rcb();
            }

            if (!users.data.length) {
                helpers.addResult(results, 0, 'No SQL users found', region);
                return rcb();
            }

            var foundRoot = false;
            users.data.forEach(user => {
                if (user.name &&
                    user.name === 'root') {
                    foundRoot = true;
                    if (user.host &&
                       (user.host === '%' ||
                        user.host === '0.0.0.0' ||
                        user.host === '/0')) {

                        helpers.addResult(results, 2,
                            'The root user has access to the instance from any host', region, user.instance);
                    } else {
                        helpers.addResult(results, 0,
                            'The root user does not have access to the instance from any host', region);
                    }
                }
            });
            if (!foundRoot) {
                helpers.addResult(results, 0, 'No root user found', region);
            }

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};