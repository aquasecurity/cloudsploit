var expect = require('chai').expect;
var restrictOutboundNetworking = require('./restrictOutboundNetworking');

const servers = [
    {
        "name": "test-server",
        "restrictOutboundNetworkAccess": "Enabled"
    }
];

const createCache = (servers, serversErr) => {
    return {
        servers: {
            listSql: {
                'eastus': {
                    err: serversErr,
                    data: servers
                }
            }
        }
    };
};

describe('restrictOutboundNetworking', function () {
    describe('run', function () {
        it('should give passing result if outbound networking restrictions are configured for the SQL server', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Outbound networking restrictions are configured for SQL server');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache(
                servers
            );

            restrictOutboundNetworking.run(cache, {}, callback);
        });

        it('should give failing result if outbound networking restrictions are not configured for SQL server', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Outbound networking restrictions are not configured for SQL server');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache(
                [
                    {
                        "name": "test-server",
                        "restrictOutboundNetworkAccess": "Disabled"
                    }
                ]
            );

            restrictOutboundNetworking.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query for SQL servers', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for SQL servers');
                expect(results[0].region).to.equal('eastus');
                done();
            };

            const cache = createCache(
                [],
                { message: 'unable to query servers' }
            );

            restrictOutboundNetworking.run(cache, {}, callback);
        });
    });
});
