var expect = require('chai').expect;
var plugin = require('./apiKeyActiveServices');

const services = [
    {
        name: 'projects/12345/services/storage.googleapis.com',
        state: 'ENABLED'
    }
]
const apiKeys = [
        {
          "name": "projects/my-project/locations/global/keys/my-key-1",
          "displayName": "API Key 1",
          "restrictions": {
            "apiTargets": [
                { "service": 'storage.googleapis.com'}
            ]
          },
        },
        {
          "name": "projects/my-project/locations/global/keys/my-key-2",
          "displayName": "API key 2",
        }
];

const createCache = (list, err, servicesList, servicesErr) => {
    return {
        apiKeys: {
            list: {
                'global': {
                    err: err,
                    data: list
                }
            },
        },
        services: {
            listEnabled: {
                'global': {
                    err: servicesErr,
                    data: servicesList
                }
            },
        },
        projects: {
            getWithNumber: {
                'global': {
                    data: [ { 
                        name: 'testproj',
                        projectNumber: 123456
                    } ]
                }
            }
        }
    }
};

describe('apiKeyActiveServices', function () {
    describe('run', function () {

        it('should give unknown result if unable to query api keys', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query API Keys for project');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                null,
                ['error'],
                services,
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if no api keys found', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No API Keys found');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                [],
                null,
                services,
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should give unknown result if unable to query services', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query services for project');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                apiKeys,
                null,
                null,
                ['error']
            );

            plugin.run(cache, {}, callback);
        });


        it('should give passing result if google cloud api key usage is restricted to active services', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('API Key usage is restricted');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                [apiKeys[0]],
                null,
                services,
                null
                );

            plugin.run(cache, {}, callback);
        });

        it('should give failing result if google cloud api key is not restricted to active services only', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('API Key usage is not restricted');
                expect(results[0].region).to.equal('global')
                done();
            };

            const cache = createCache(
                [apiKeys[1]],
                null,
                services,
                null
                );

            plugin.run(cache, {}, callback);
        });

    })
});

