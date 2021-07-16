var expect = require('chai').expect;
var plugin = require('./instancePublicAccess');

const createCache = (instanceData, error) => {
    return {
        instances: {
            compute: {
                list: {
                    'us-central1-a': {
                        data: instanceData,
                        err: error
                    }
                }
            }
        },
        projects: {
            get: {
                'global': {
                    data: 'testproj'
                }
            }
        }
    }
};

describe('instancePublicAccess', function () {
    describe('run', function () {

        it('should give unknown if an instance error occurs', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(3);
                expect(results[0].message).to.include('Unable to query instances');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [],
                ['null']
            );

            plugin.run(cache, {}, callback);
        });

        it('should pass no VM Instances', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('No instances found');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [],
                null
            );

            plugin.run(cache, {}, callback);
        });

        it('should fail if instance public access is enabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(2);
                expect(results[0].message).to.include('Public access is enabled for the instance');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [
                    {
                        id: "1719867382827328572",
                        name: "testing-instance",
                        zone: "https://www.googleapis.com/compute/v1/projects/akhtar-dev-aqua/zones/us-central1-a",
                        networkInterfaces: [
                          {
                            network: "https://www.googleapis.com/compute/v1/projects/akhtar-dev-aqua/global/networks/default",
                            subnetwork: "https://www.googleapis.com/compute/v1/projects/akhtar-dev-aqua/regions/us-central1/subnetworks/default",
                            networkIP: "10.128.0.3",
                            name: "nic0",
                            accessConfigs: [
                              {
                                type: "ONE_TO_ONE_NAT",
                                name: "External NAT",
                                natIP: "34.72.52.155",
                                networkTier: "PREMIUM",
                                kind: "compute#accessConfig",
                              },
                            ],
                            fingerprint: "d6n46SySJeI=",
                            kind: "compute#networkInterface",
                          },
                        ],
                    }
                ],
                null
            );

            plugin.run(cache, {}, callback);
        })

        it('should pass if instance public access is disabled', function (done) {
            const callback = (err, results) => {
                expect(results.length).to.be.above(0);
                expect(results[0].status).to.equal(0);
                expect(results[0].message).to.include('Public access is disabled for the instance');
                expect(results[0].region).to.equal('us-central1');
                done()
            };

            const cache = createCache(
                [
                    {
                        id: "3736210870233209587",
                        name: "testing-instance2",
                        zone: "https://www.googleapis.com/compute/v1/projects/akhtar-dev-aqua/zones/us-central1-a",
                        networkInterfaces: [
                          {
                            network: "https://www.googleapis.com/compute/v1/projects/akhtar-dev-aqua/global/networks/default",
                            subnetwork: "https://www.googleapis.com/compute/v1/projects/akhtar-dev-aqua/regions/us-central1/subnetworks/default",
                            networkIP: "10.128.0.4",
                            name: "nic0",
                            fingerprint: "grGInqLIF64=",
                            kind: "compute#networkInterface",
                          },
                        ],
                      }
                ]
            );

            plugin.run(cache, {}, callback);
        })

    })
})