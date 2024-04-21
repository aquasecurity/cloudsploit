var expect = require('chai').expect;
var auth = require('./flexibleServerConnectionThrottle');

const servers = [
    {
        "id": "/subscriptions/12345/resourceGroups/Default/providers/Microsoft.DBforPostgreSQL/flexibleServers/test-server",
        "type": "Microsoft.DBforPostgreSQL/flexibleServers"
    },
]

const configurations = [
    {
        id: '/subscriptions/22345/resourceGroups/test2/providers/Microsoft.DBforPostgreSQL/flexibleServers/testfs/configurations/password_encryption',
        name: 'connection_throttle.enable',
        type: 'Microsoft.DBforPostgreSQL/flexibleServers/configurations',
        value: 'ON',
        description: 'Enables temporary connection throttling per IP for too many login failures.',
        defaultValue: 'OFF',
        dataType: 'Enumeration',
        allowedValues: 'on,off',
        source: 'user-override',
        isDynamicConfig: true,
        isReadOnly: false,
        isConfigPendingRestart: false
    },

    {
        id: '/subscriptions/12345/resourceGroups/test-rg/providers/Microsoft.DBforPostgreSQL/flexibleServers/testfs/configurations/password_encryption',
        name: 'connection_throttle.enable',
        type: 'Microsoft.DBforPostgreSQL/flexibleServers/configurations',
        value: 'OFF',
        description: 'Enables temporary connection throttling per IP for too many login failures.',
        defaultValue: 'OFF',
        dataType: 'Enumeration',
        allowedValues: 'on,off',
        source: 'user-override',
        isDynamicConfig: true,
        isReadOnly: false,
        isConfigPendingRestart: false
    }

    
]

const createCache = (err, list, configuration) => {
    return {
        servers: {
            listPostgresFlexibleServer: {
                'eastus': {
                    err: err,
                    data: list
                }
            }
        },
        flexibleServersConfigurations: {
            listByPostgresServer: {
                'eastus': configuration
            }
        }
    }
};

describe('flexibleServerConnectionThrottle', function() {
    describe('run', function() {
        it('should PASS if no existing servers found', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing PostgreSQL flexible servers found');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                [],
                {}
            );

            auth.run(cache, {}, callback);
        });

        it('should give UNKNOWN if unable to query for PostgreSQL flexible Servers', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                null,
                {}
            );

            auth.run(cache, {}, callback);
        })

        it('should give UNKNOWN if unable to query for configurations', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                servers,
                {}
            );

            auth.run(cache, {}, callback);
        })

        it('should FAIL if PostgreSQL server has connection throttle not enabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('PostgreSQL flexible server does not have connection throttling enabled');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                servers,
                {
                    "/subscriptions/12345/resourceGroups/Default/providers/Microsoft.DBforPostgreSQL/flexibleServers/test-server": {
                        data: [configurations[1]]
                    }
                }
            );

            auth.run(cache, {}, callback);
        });

        it('should PASS if PostgreSQL server has connection throttle enabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('PostgreSQL flexible server has connection throttling enabled');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                null,
                servers,
                {
                    "/subscriptions/12345/resourceGroups/Default/providers/Microsoft.DBforPostgreSQL/flexibleServers/test-server": {
                        data: [configurations[0]]
                    }
                }
            );

            auth.run(cache, {}, callback);
        });

        
    })
})