var expect = require('chai').expect;
var plugin = require('./projectAPIKeys');


const apiKeys = [
        {
          "name": "projects/my-project/locations/global/keys/my-key-1",
          "displayName": "API Key 1",
          "restrictions": {
            "browserKeyRestrictions": {
                "allowedReferrers" : [ "www.google.com"]
            }
          },
        },
        {
          "name": "projects/my-project/locations/global/keys/my-key-2",
          "displayName": "API key 2",
        }
];

const createCache = (list, err) => {
    return {
        apiKeys: {
            list: {
                'global': {
                    err: err,
                    data: list
                }
            },
        },
        projects: {
            get: {
                'global': {
                    data: [ { name: 'testproj' } ]
                }
            }
        }
    }
};

describe('projectAPIKeys', function () {
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
                ['error']
            );

            plugin.run(cache, {}, callback);
        });

        it('should give passing result if no api keys exist in the project', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('API Keys do not exist in the project');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                [],
                null
            );

            plugin.run(cache, {}, callback);
        });

    
        it('should give failing result if api keys exist in project', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('API Keys exist in the project');
                expect(results[0].region).to.equal('global')
                done();
            };

            const cache = createCache(
                [apiKeys[1]],
                null);

            plugin.run(cache, {}, callback);
        });

    })
});

