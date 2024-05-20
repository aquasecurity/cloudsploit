var expect = require('chai').expect;
var auth = require('./flexibleServerLogDisconnections');

const servers = [
    {
        "id": "/subscriptions/12345/resourceGroups/Default/providers/Microsoft.DBforPostgreSQL/flexibleServers/test-server",
        "type": "Microsoft.DBforPostgreSQL/flexibleServers"
    },
]

const configurations = [
    {
        "id": "/subscriptions/12345/resourceGroups/tests/providers/Microsoft.DBforPostgreSQL/servers/test1/configurations/log_checkpoints",
        "name": "log_disconnections",
        "type": "Microsoft.DBforPostgreSQL/servers/configurations",
        "value": "on",
        "description": "Logs each checkpoint.",
        "defaultValue": "on",
        "dataType": "Boolean",
        "allowedValues": "on,off",
        "source": "system-default",
        "location": "ukwest",
        "storageAccount": {
        "name": "gioservertest1"
        }
    },

    {
        "id": "/subscriptions/12345/resourceGroups/Default/providers/Microsoft.DBforPostgreSQL/servers/giost1/configurations/log_checkpoints",
        "name": "log_disconnections",
        "type": "Microsoft.DBforPostgreSQL/servers/configurations",
        "value": "off",
        "description": "Logs each checkpoint.",
        "defaultValue": "on",
        "dataType": "Boolean",
        "allowedValues": "on,off",
        "source": "system-default",
        "location": "ukwest",
        "storageAccount": {
        "name": "gioservertest1"
        }
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

describe('flexibleServerLogDisconnections', function() {
    describe('run', function() {
        it('should PASS if no existing servers found', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing PostgreSQL Flexible Servers found');
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

        it('should FAIL if PostgreSQL server has log disconnections not enabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Log disconnections is disabled for the PostgreSQL Flexible Server configuration');
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

        it('should PASS if PostgreSQL server has log disconnection enabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Log disconnections is enabled for the PostgreSQL Flexible Server configuration');
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