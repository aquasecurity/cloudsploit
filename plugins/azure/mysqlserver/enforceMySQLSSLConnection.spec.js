var expect = require('chai').expect;
var server = require('./enforceMySQLSSLConnection');

const servers = [
    {
        "sku": [Object],
        "location": 'eastus',
        "tags": {},
        "id": '/subscriptions/123/resourceGroups/aqua-resource-group/prov"id"ers/Microsoft.DBforMySQL/servers/test-server',
        "name": 'test-server',
        "type": 'Microsoft.DBforMySQL/servers',
        "sslEnforcement": 'Enabled',
        "userVisibleState": 'Ready',
        "fullyQualifiedDomainName": 'test-server.mysql.database.azure.com',
        "earliestRestoreDate": '2021-03-14T17:53:38.68+00:00',
        "infrastructureEncryption": 'Disabled',
        "publicNetworkAccess": 'Enabled'
    },
    {
        "sku": [Object],
        "location": 'eastus',
        "tags": {},
        "id": '/subscriptions/123/resourceGroups/aqua-resource-group/providers/Microsoft.DBforMySQL/servers/test-server',
        "name": 'test-server',
        "type": 'Microsoft.DBforMySQL/servers',
        "sslEnforcement": 'Disabled',
        "userVisibleState": 'Ready',
        "fullyQualifiedDomainName": 'test-server.mysql.database.azure.com',
        "earliestRestoreDate": '2021-03-14T17:53:38.68+00:00',
        "infrastructureEncryption": 'Disabled',
        "publicNetworkAccess": 'Enabled'
    }
];

const createCache = (server) => {
    return {
        servers: {
            listMysql: {
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
            listMysql: {
                'eastus': {}
            }
        }
    };
};

describe('enforceMySQLSSLConnection', function() {
    describe('run', function() {
        it('should give passing result if no servers', function(done) {
            const cache = createCache([]);
            server.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No existing MySQL servers found');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give failing result if MySQL Server does not enforce SSL connection', function(done) {
            const cache = createCache([servers[1]]);
            server.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('The MySQL server does not enforce SSL connections');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give unknown result if unable to query for MySQL servers', function(done) {
            const cache = createErrorCache();
            server.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for MySQL servers:');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });

        it('should give passing result if MySQL Server enforces SSL connection', function(done) {
            const cache = createCache([servers[0]]);
            server.run(cache, {}, (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('The MySQL server enforces SSL connections');
                expect(results[0].region).to.equal('eastus');
                done();
            });
        });
    });
}); 