var expect = require('chai').expect;
var enableATP = require('./enableATP');

const servers = [
    {
        "id": "/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server",
    }
];

const advancedThreatProtectionSettings = [
    {
        id: '/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server/advancedThreatProtectionSettings/Default',
        name: 'Default',
        type: 'Microsoft.Sql/servers/advancedThreatProtectionSettings',
        state: 'Enabled',
        creationTime: '2022-05-12T10:08:23.127Z'
    },
    {
        id: '/subscriptions/123/resourceGroups/test-rg/providers/Microsoft.Sql/servers/test-server/advancedThreatProtectionSettings/Default',
        name: 'Default',
        type: 'Microsoft.Sql/servers/advancedThreatProtectionSettings',
        state: 'Disabled',
        creationTime: '2022-05-12T10:08:23.127Z'
    },
];

const createCache = (servers, policies, serversErr, policiesErr) => {
    const serverId = (servers && servers.length) ? servers[0].id : null;
    return {
        servers: {
            listSql: {
                'eastus': {
                    err: serversErr,
                    data: servers
                }
            }
        },
        advancedThreatProtectionSettings: {
            listByServer: {
                'eastus': {
                    [serverId]: {
                        err: policiesErr,
                        data: policies
                    }
                }
            }
        }
    }
};

describe('enableATP', function() {
    describe('run', function() {
        it('should give passing result if no SQL servers found', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No SQL servers found');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                []
            );

            enableATP.run(cache, {}, callback);
        });

        it('should give failing result if no Database Advanced Threat Protection settings found', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('No Advanced Threat Protection setting found');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                servers,
                []
            );

            enableATP.run(cache, {}, callback);
        });

        it('should give failing result if Advanced Threat Protection for the SQL server is disabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Advanced Threat Protection for the SQL server is disabled');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                servers,
                [advancedThreatProtectionSettings[1]]
            );

            enableATP.run(cache, {}, callback);
        });

        it('should give passing result if Advanced Threat Protection for the SQL server is enabled', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Advanced Threat Protection for the SQL server is enabled');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                servers,
                [advancedThreatProtectionSettings[0]]
            );

            enableATP.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query for SQL servers', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for SQL servers');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                servers,
                [],
                { message: 'unable to query servers'}
            );

            enableATP.run(cache, {}, callback);
        });

        it('should give unknown result if Unable to query for Database Advanced Threat Protection settings', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for Database Advanced Threat Protection settings');
                expect(results[0].region).to.equal('eastus');
                done()
            };

            const cache = createCache(
                servers,
                [],
                null,
                { message: 'Unable to query for Database Advanced Threat Protection settings'}
            );

            enableATP.run(cache, {}, callback);
        });
    })
});
