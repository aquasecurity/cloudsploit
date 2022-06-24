var expect = require('chai').expect;
var autoFailoverGroupsEnabled = require('./autoFailoverGroupsEnabled');

const servers = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Sql/servers/test-server',
        'name': 'test-server',
        'location': 'eastus'
    }
];

const failoverGroups = [
    {
        'id': '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.Sql/servers/test-server/failoverGroups/test-group',
        'name': 'test-group',
        'type': 'Microsoft.Sql/servers/failoverGroups'
    }
];


const createCache = (servers, failoverGroups) => {
    let server = {};
    let groups = {};
    if (servers) {
        server['data'] = servers;
        if (servers.length > 0 && failoverGroups) {
            groups[servers[0].id] = {
                data: failoverGroups
            };
        }
    }
    return {
        servers: {
            listSql: {
                'eastus': server
            }
        },
        failoverGroups: {
            listByServer: {
                'eastus': groups
            }
        }
    };
};

describe('autoFailoverGroupsEnabled', function() {
    describe('run', function() {
        it('should give passing result if no SQL servers', function(done) {
            const cache = createCache([], null);
            autoFailoverGroupsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No SQL servers found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for SQL servers', function(done) {
            const cache = createCache(null);
            autoFailoverGroupsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for SQL servers:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for failover groups', function(done) {
            const cache = createCache([servers[0]], null);
            autoFailoverGroupsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for auto-failover groups:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if auto-failover groups are configured', function(done) {
            const cache = createCache([servers[0]], [failoverGroups[0]]);
            autoFailoverGroupsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Auto-failover groups are configured for the SQL server');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if no auto-failover groups found', function(done) {
            const cache = createCache([servers[0]], []);
            autoFailoverGroupsEnabled.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Auto-failover groups are not configured for the SQL server');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
});