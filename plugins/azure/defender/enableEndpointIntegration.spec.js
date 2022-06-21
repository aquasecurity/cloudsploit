var assert = require('assert');
var expect = require('chai').expect;
var auth = require('./enableEndpointIntegration');

const createCache = (err, data) => {
    return {
        securityCenter: {
            list: {
                'global': {
                    err: err,
                    data: data
                }
            }
        }
    }
};

describe('enableEndpointIntegration', function() {
    describe('run', function() {
        it('should give passing result if no settings found', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No Defender Settings information found');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                []
            );

            auth.run(cache, {}, callback);
        });

        it('should give failing result if Endpoint integration is not enabled for Azure Defender', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Endpoint integration is not enabled for Microsoft Defender');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        id: '/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/providers/Microsoft.Security/settings/WDATP',
                        name: 'WDATP',
                        type: 'Microsoft.Security/settings',
                        kind: 'DataExportSettings',
                        enabled: false
                    },
                ]
            );

            auth.run(cache, {}, callback);
        });

        it('should give passing result if Endpoint integration is enabled for Azure Defender', function(done) {
            const callback = (err, results) => {
                expect(results.length).to.equal(1);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Endpoint integration is enabled for Microsoft Defender');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                [
                    {
                        id: '/subscriptions/dce7d0ad-ebf6-437f-a3b0-28fc0d22117e/providers/Microsoft.Security/settings/WDATP',
                        name: 'WDATP',
                        type: 'Microsoft.Security/settings',
                        kind: 'DataExportSettings',
                        enabled: true
                    },
                ]
            );

            auth.run(cache, {}, callback);
        })
    })
});
