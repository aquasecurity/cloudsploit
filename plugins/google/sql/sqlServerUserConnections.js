var async = require('async');
var helpers = require('../../../helpers/google');

module.exports = {
    title: 'SQL Server User Connections Flag',
    category: 'SQL',
    domain: 'Databases',
    severity: 'Medium',
    description: 'Ensure that user connections database flag for Cloud SQL Server Instances is set to desired value.',
    more_info: 'The user connection flag represents the maximum number of simultaneous connections that are allowed on an SQL Server instance. By default, it is set to 0 which means maximum connections are allowed. If the user connections flag is set to a limiting value, SQL Server will not allow any connections above the limit. If the connections are at the limit and will drop any new requests causing potential data loss or outages.',
    link: 'https://cloud.google.com/sql/docs/sqlserver/flags',
    recommended_action: 'Ensure that all SQL Server database instances have user connections flag set to your organization recommended value.',
    apis: ['sql:list'],
    settings: {
        min_user_connections: {
            name: 'Minimum User Connections',
            description: 'Return a passing result if the user connections value is greater than or equal to this value. 0 means maximum.',
            // eslint-disable-next-line
            regex: '^(3276[0-7]|327[0-5]\d|32[0-6]\d{2}|3[01]\d{3}|[12]\d{4}|[1-9]\d{3}|[1-9]\d{2}|[1-9]\d|\d)$',
            default: '0'
        }
    },
    realtime_triggers:['cloudsql.instances.update','cloudsql.instances.delete','cloudsql.instances.create'],
    
    run: function(cache, settings, callback) {
        var results = [];
        var source = {};
        var regions = helpers.regions();
        let min_user_connections = parseInt(settings.min_user_connections || this.settings.min_user_connections.default);

        let projects = helpers.addSource(cache, source,
            ['projects','get', 'global']);

        if (!projects || projects.err || !projects.data) {
            helpers.addResult(results, 3,
                'Unable to query for projects: ' + helpers.addError(projects), 'global', null, null, projects.err);
            return callback(null, results, source);
        }

        let project = projects.data[0].name;

        async.each(regions.sql, function(region, rcb){
            let sqlInstances = helpers.addSource(
                cache, source, ['sql', 'list', region]);

            if (!sqlInstances) return rcb();

            if (sqlInstances.err || !sqlInstances.data) {
                helpers.addResult(results, 3, 'Unable to query SQL instances: ' + helpers.addError(sqlInstances), region);
                return rcb();
            }

            if (!sqlInstances.data.length) {
                helpers.addResult(results, 0, 'No SQL instances found', region);
                return rcb();
            }

            sqlInstances.data.forEach(sqlInstance => {
                if (sqlInstance.instanceType && sqlInstance.instanceType.toUpperCase() === 'READ_REPLICA_INSTANCE') return;

                let resource = helpers.createResourceName('instances', sqlInstance.name, project);

                if (sqlInstance.databaseVersion && !sqlInstance.databaseVersion.toUpperCase().startsWith('SQLSERVER')) {
                    helpers.addResult(results, 0, 'SQL instance database type is not of SQL Server type', region, resource);
                    return;
                }
                let hasResult = false;
                if (sqlInstance.settings &&
                    sqlInstance.settings.databaseFlags) {
                    let found = sqlInstance.settings.databaseFlags.find(flag => flag.name && flag.name == 'user connections' &&
                        flag.value);
                    if (found) {
                        let maxConnections = parseInt(found.value);
                        if (!([0, 32767].includes(maxConnections))) {
                            hasResult = true;
                            if (maxConnections >= min_user_connections && min_user_connections !== 0) {
                                helpers.addResult(results, 0,
                                    `SQL instance has "user connections" flag set to ${maxConnections} which is greater than or equal to ${min_user_connections === 0 ? 'maximum' : min_user_connections}`, region, resource);
                            } else {
                                helpers.addResult(results, 2,
                                    `SQL instance has "user connections" flag set to ${maxConnections} which is less than ${min_user_connections === 0 ? 'maximum' : min_user_connections}`, region, resource);
                            }
                        }
                    } 
                } 
                if (!hasResult) {
                    helpers.addResult(results, 0,
                        'SQL instance has "user connections" flag set to allow maximum number of connections', region, resource);
                }
            });

            rcb();
        }, function(){
            // Global checking goes here
            callback(null, results, source);
        });
    }
};

