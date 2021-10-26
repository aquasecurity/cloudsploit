var expect = require('chai').expect;
var plugin = require('./enableUsageExport');

const createCache = (projectData, error) => {
    return {
        projects: {
            get: {
                'global': {
                    data: projectData,
                    error: error
                }
            }
        }
    }
}

describe('enableUsageExport', function () {
    describe('run', function () {
        it('should return unknown if a project error occurs', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query for projects');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                [],
                ['error']
            );

            plugin.run(cache, {}, callback);
        });


        it('should fail if usage export is diabled for project', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Enable Usage Export is not configured for project');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                [
                    {
                        kind: 'compute#project',
                        id: '11111',
                        creationTimestamp: '2021-05-07T12:09:27.812-07:00',
                        name: 'project-1',    
                        xpnProjectStatus: 'UNSPECIFIED_XPN_PROJECT_STATUS',
                        defaultNetworkTier: 'PREMIUM'
                    }
                ],
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should pass if usage export is enabled for project', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Enable Usage Export is configured for project');
                expect(results[0].region).to.equal('global');
                done()
            };

            const cache = createCache(
                [
                    {
                        kind: 'compute#project',
                        id: '11111',
                        creationTimestamp: '2021-05-07T12:09:27.812-07:00',
                        name: 'project-1',    
                        usageExportLocation: { bucketName: 'project-1-my-bucket-1', reportNamePrefix: '' },
                        xpnProjectStatus: 'UNSPECIFIED_XPN_PROJECT_STATUS',
                        defaultNetworkTier: 'PREMIUM'
                    }
                ]
            );

            plugin.run(cache, {}, callback);
        })

    })
})