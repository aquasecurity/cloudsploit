var expect = require('chai').expect;
var server = require('./mysqlFlexibleServerHasTags');

const servers = [
    {
        "id": "/subscriptions/12345/resourceGroups/Default/providers/Microsoft.DBforMySQL/flexibleServers/test-server",
        "type": "Microsoft.DBforMySQL/flexibleServers",
        "name": 'test-server',
        "tags": {"key": "value"},
    },
    {
        "id": "/subscriptions/12345/resourceGroups/Default/providers/Microsoft.DBforMySQL/flexibleServers/test-server",
        "type": "Microsoft.DBforMySQL/flexibleServers",
        "name": 'test-server',
        "tags": {},
    }
];

const createCache = (server) => {
    return {
        servers: {
            listMysqlFlexibleServer: {
                'eastus': {
                    data: server
                }
            }
        }
    };
};

const createErrorCache = () => {
    return {
        servers: {
            listMysqlFlexibleServer: {
                'eastus': {}
            }
        }
    };
};

describe('mysqlServerHasTags', function() {
    describe('run', function() {
        it('should give passing result if no servers found', function(done) {
            const cache = createCache([]);
            server.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing MySQL flexible servers found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if MySQL Server does not have tags', function(done) {
            const cache = createCache([servers[1]]);
            server.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('MySQL Flexible server does not have tags associated');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for MySQL servers', function(done) {
            const cache = createErrorCache();
            server.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for MySQL flexible servers:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if MySQL Server has tags', function(done) {
            const cache = createCache([servers[0]]);
            server.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('MySQL Flexible server has tags associated');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
}); 