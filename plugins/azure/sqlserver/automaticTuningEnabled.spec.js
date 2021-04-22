var expect = require('chai').expect;
var automaticTuningEnabled = require('./automaticTuningEnabled');

const servers = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Sql/servers/test-server',
        'name': 'test-server',
        'location': 'eastus'
    }
];

const automaticTuningSetting = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Sql/servers/test-server/automaticTuning/current',
        'name': 'current',
        'type': 'Microsoft.Sql/servers/automaticTuning',
        'desiredState': 'Auto',
        'actualState': 'Auto',
        'options': {
            'createIndex': {
                'desiredState': 'Default',
                'actualState': 'Off',
                'reasonCode': 2,
                'reasonDesc': 'AutoConfigured'
            },
            'dropIndex': {
                'desiredState': 'Default',
                'actualState': 'Off',
                'reasonCode': 2,
                'reasonDesc': 'AutoConfigured'
            },
            'forceLastGoodPlan': {
                'desiredState': 'Default',
                'actualState': 'On',
                'reasonCode': 2,
                'reasonDesc': 'AutoConfigured'
            },
            'maintainIndex': {
                'desiredState': 'Off',
                'actualState': 'Off'
            }
        }
    },
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Sql/servers/test-server/automaticTuning/current',
        'name': 'current',
        'type': 'Microsoft.Sql/servers/automaticTuning',
        'desiredState': 'Auto',
        'actualState': 'Auto',
        'options': {
            'createIndex': {
                'desiredState': 'On',
                'actualState': 'On'
            },
            'dropIndex': {
                'desiredState': 'On',
                'actualState': 'On'
            },
            'forceLastGoodPlan': {
                'desiredState': 'On',
                'actualState': 'On'
            },
            'maintainIndex': {
                'desiredState': 'Off',
                'actualState': 'Off'
            }
        }
    }
];


const createCache = (servers, tuningConfigs) => {
    let server = {};
    let configs = {};
    if (servers) {
        server['data'] = servers;
        if (servers.length > 0 && tuningConfigs) {
            configs[servers[0].id] = {
                data: tuningConfigs
            };
        }
    }
    return {
        servers: {
            listSql: {
                'eastus': server
            }
        },
        serverAutomaticTuning: {
            get: {
                'eastus': configs
            }
        }
    };
};

describe('automaticTuningEnabled', function() {
    describe('run', function() {
        it('should give passing result if no SQL servers', function(done) {
            const cache = createCache([]);
            automaticTuningEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No SQL servers found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for SQL servers', function(done) {
            const cache = createCache(null);
            automaticTuningEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for SQL servers:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if no automatic tuning configurations found for SQL server', function(done) {
            const cache = createCache([servers[0]], {});
            automaticTuningEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No automatic tuning configurations found for SQL server');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for SQL server automatic tuning configurations', function(done) {
            const cache = createCache([servers[0]], null);
            automaticTuningEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for SQL server automatic tuning configurations');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if SQL server has Azure automatic tuning enabled', function(done) {
            const cache = createCache([servers[0]], automaticTuningSetting[0]);
            automaticTuningEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('SQL server has Azure automatic tuning enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if SQL server does not have Azure automatic tuning enabled', function(done) {
            const cache = createCache([servers[0]], automaticTuningSetting[1]);
            automaticTuningEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('SQL server does not have Azure automatic tuning enabled');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});